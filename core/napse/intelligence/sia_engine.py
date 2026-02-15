"""
SIA Engine — Semantic Intent Attribution Orchestrator

Wires EntityGraph + GraphEmbedder + IntentDecoder + BayesianScorer
into a unified pipeline. Subscribes to ALL NAPSE EventBus types
and processes per-entity through the SIA pipeline.

Pipeline:
    Event → EntityGraph.add_*() → GraphEmbedder.embed_entity()
         → IntentDecoder.observe() → BayesianScorer.update_belief()
         → If score > 0.92: emit ENTITY_SANDBOXED via EventBus
         → Emit AEGIS StandardSignal for GUARDIAN/MEDIC

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .entity_graph import EntityGraph
from .graph_embedder import GraphEmbedder
from .intent_decoder import IntentDecoder, IntentPhase, IntentSequence
from .bayesian_scorer import BayesianScorer

logger = logging.getLogger(__name__)

# Minimum events before processing through SIA pipeline
MIN_EVENTS_FOR_SIA = 3

# How often to process each entity (avoid over-processing)
PROCESS_INTERVAL_S = 5.0


class SIAEngine:
    """
    Semantic Intent Attribution engine.

    Orchestrates the full SIA pipeline:
    1. Ingest network events into EntityGraph
    2. Compute entity embeddings via GraphEmbedder
    3. Decode intent phases via IntentDecoder (HMM)
    4. Evolve risk scores via BayesianScorer
    5. Trigger sandbox when threshold exceeded
    6. Emit signals to AEGIS
    """

    def __init__(
        self,
        window_hours: float = 24.0,
        embedding_dim: int = 64,
        sandbox_threshold: float = 0.92,
        max_nodes: int = 10000,
    ):
        # Core components
        self.graph = EntityGraph(
            window_hours=window_hours,
            max_nodes=max_nodes,
        )
        self.embedder = GraphEmbedder(
            graph=self.graph,
            embedding_dim=embedding_dim,
        )
        self.decoder = IntentDecoder()
        self.scorer = BayesianScorer(
            sandbox_threshold=sandbox_threshold,
        )

        # Per-entity processing timestamps
        self._last_processed: Dict[str, float] = {}
        self._lock = threading.Lock()

        # Callbacks
        self._signal_callback: Optional[Callable] = None
        self._sandbox_callback: Optional[Callable] = None

        # Wire sandbox trigger
        self.scorer.on_sandbox_trigger(self._on_sandbox_trigger)

        self._stats = {
            "events_ingested": 0,
            "entities_processed": 0,
            "intents_detected": 0,
            "sandbox_triggers": 0,
        }

        logger.info(
            "SIAEngine initialized (window=%.1fh, dim=%d, threshold=%.2f)",
            window_hours, embedding_dim, sandbox_threshold,
        )

    # ------------------------------------------------------------------
    # Callback Registration
    # ------------------------------------------------------------------

    def set_signal_callback(self, callback: Callable) -> None:
        """Set callback for emitting AEGIS StandardSignals."""
        self._signal_callback = callback

    def set_sandbox_callback(self, callback: Callable) -> None:
        """Set callback for sandbox trigger events."""
        self._sandbox_callback = callback

    # ------------------------------------------------------------------
    # NAPSE EventBus Integration
    # ------------------------------------------------------------------

    def register_with_event_bus(self, event_bus) -> None:
        """Subscribe to all relevant NAPSE EventBus event types."""
        from core.napse.synthesis.event_bus import EventType

        event_bus.subscribe(EventType.CONNECTION, self._on_connection)
        event_bus.subscribe(EventType.DNS, self._on_dns)
        event_bus.subscribe(EventType.ALERT, self._on_alert)
        event_bus.subscribe(EventType.TLS, self._on_tls)
        event_bus.subscribe(EventType.SSH, self._on_ssh)
        event_bus.subscribe(EventType.HTTP, self._on_http)
        event_bus.subscribe(EventType.FLOW_METADATA, self._on_flow_metadata)

        if hasattr(EventType, "HONEYPOT_TOUCH"):
            event_bus.subscribe(EventType.HONEYPOT_TOUCH, self._on_honeypot_touch)

        logger.info("SIAEngine registered with NAPSE EventBus")

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_connection(self, event_type, conn) -> None:
        """Handle connection events."""
        src_ip = getattr(conn, "id_orig_h", "")
        dst_ip = getattr(conn, "id_resp_h", "")
        dst_port = getattr(conn, "id_resp_p", 0)
        proto = getattr(conn, "proto", "tcp")
        service = getattr(conn, "service", "")
        orig_bytes = getattr(conn, "orig_bytes", 0)
        resp_bytes = getattr(conn, "resp_bytes", 0)
        conn_state = getattr(conn, "conn_state", "")

        if not src_ip:
            return

        self.graph.add_connection_event(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
            proto=proto, service=service,
            orig_bytes=orig_bytes, resp_bytes=resp_bytes,
            conn_state=conn_state,
        )
        self._stats["events_ingested"] += 1
        self._maybe_process_entity(src_ip)

    def _on_dns(self, event_type, dns) -> None:
        """Handle DNS events."""
        src_ip = getattr(dns, "id_orig_h", "")
        query = getattr(dns, "query", "")
        answers = getattr(dns, "answers", [])

        if not src_ip or not query:
            return

        self.graph.add_dns_event(src_ip, query, answers)
        self._stats["events_ingested"] += 1
        self._maybe_process_entity(src_ip)

    def _on_alert(self, event_type, alert) -> None:
        """Handle alert events — high-signal for SIA."""
        if isinstance(alert, dict):
            src_ip = alert.get("src_ip", "")
            severity = alert.get("alert_severity", "MEDIUM")
        else:
            src_ip = getattr(alert, "src_ip", "")
            severity = str(getattr(alert, "alert_severity", "MEDIUM"))

        if not src_ip:
            return

        self.graph.add_alert_event(src_ip, severity)
        self._stats["events_ingested"] += 1
        # Force immediate processing on alerts
        self._process_entity(src_ip)

    def _on_tls(self, event_type, tls) -> None:
        """Handle TLS events."""
        src_ip = getattr(tls, "id_orig_h", "")
        dst_ip = getattr(tls, "id_resp_h", "")
        dst_port = getattr(tls, "id_resp_p", 443)

        if not src_ip:
            return

        self.graph.add_connection_event(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
            proto="tcp", service="tls",
        )
        self._stats["events_ingested"] += 1
        self._maybe_process_entity(src_ip)

    def _on_ssh(self, event_type, ssh) -> None:
        """Handle SSH events."""
        src_ip = getattr(ssh, "id_orig_h", "")
        dst_ip = getattr(ssh, "id_resp_h", "")

        if not src_ip:
            return

        self.graph.add_connection_event(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=22,
            proto="tcp", service="ssh",
        )
        self._stats["events_ingested"] += 1
        self._maybe_process_entity(src_ip)

    def _on_http(self, event_type, http) -> None:
        """Handle HTTP events."""
        src_ip = getattr(http, "id_orig_h", "")
        dst_ip = getattr(http, "id_resp_h", "")
        dst_port = getattr(http, "id_resp_p", 80)

        if not src_ip:
            return

        self.graph.add_connection_event(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
            proto="tcp", service="http",
        )
        self._stats["events_ingested"] += 1
        self._maybe_process_entity(src_ip)

    def _on_flow_metadata(self, event_type, metadata) -> None:
        """Handle lightweight flow metadata."""
        if not isinstance(metadata, dict):
            return

        src_ip = metadata.get("src_ip", "")
        dst_ip = metadata.get("dst_ip", "")
        dst_port = metadata.get("dest_port", 0)

        if not src_ip:
            return

        self.graph.add_connection_event(
            src_ip=src_ip, dst_ip=dst_ip or "unknown",
            dst_port=dst_port, proto=metadata.get("proto", "tcp"),
        )
        self._stats["events_ingested"] += 1
        self._maybe_process_entity(src_ip)

    def _on_honeypot_touch(self, event_type, touch) -> None:
        """Handle honeypot touch events — high-signal."""
        if isinstance(touch, dict):
            src_ip = touch.get("source_ip", "")
            dst_port = touch.get("dest_port", 0)
        else:
            src_ip = getattr(touch, "source_ip", "")
            dst_port = getattr(touch, "dest_port", 0)

        if not src_ip:
            return

        self.graph.add_connection_event(
            src_ip=src_ip, dst_ip="honeypot", dst_port=dst_port,
            proto="tcp", service="honeypot",
        )
        self.graph.add_alert_event(src_ip, "HIGH")
        self._stats["events_ingested"] += 1
        self._process_entity(src_ip)

    # ------------------------------------------------------------------
    # SIA Processing Pipeline
    # ------------------------------------------------------------------

    def _maybe_process_entity(self, entity_id: str) -> None:
        """Process entity if enough time has passed since last processing."""
        now = time.time()
        with self._lock:
            last = self._last_processed.get(entity_id, 0)
            if now - last < PROCESS_INTERVAL_S:
                return

        self._process_entity(entity_id)

    def _process_entity(self, entity_id: str) -> Optional[IntentSequence]:
        """Run full SIA pipeline on an entity.

        Pipeline: Graph → Embedding → Intent → Bayesian → Signal
        """
        node = self.graph.get_node(entity_id)
        if not node or node.event_count < MIN_EVENTS_FOR_SIA:
            return None

        with self._lock:
            self._last_processed[entity_id] = time.time()

        self._stats["entities_processed"] += 1

        # Step 1: Compute embedding
        embedding = self.embedder.embed_entity(entity_id)

        # Step 2: Compute deviation from Golden Harmonic
        deviation = self.embedder.compute_deviation(entity_id)

        # Step 3: Get features for HMM
        features = node.get_feature_vector()

        # Step 4: Decode intent via HMM
        intent = self.decoder.observe(
            entity_id=entity_id,
            features=features,
            embedding=embedding,
            deviation=deviation,
        )

        # Step 5: Update Bayesian belief
        posterior = self.scorer.update_belief(
            entity_id=entity_id,
            phase=intent.current_phase,
            confidence=intent.current_confidence,
            source="sia",
        )

        # Step 6: Emit signal if intent detected
        if intent.is_attacking:
            self._stats["intents_detected"] += 1
            self._emit_intent_signal(entity_id, intent, posterior)

        return intent

    def process_entity(self, entity_id: str) -> Optional[IntentSequence]:
        """Public interface to process a specific entity."""
        return self._process_entity(entity_id)

    # ------------------------------------------------------------------
    # Signal Emission
    # ------------------------------------------------------------------

    def _emit_intent_signal(
        self,
        entity_id: str,
        intent: IntentSequence,
        risk_score: float,
    ) -> None:
        """Emit AEGIS signal when intent is detected."""
        if not self._signal_callback:
            return

        try:
            from core.aegis.types import StandardSignal

            severity = "MEDIUM"
            if risk_score >= 0.8:
                severity = "CRITICAL"
            elif risk_score >= 0.5:
                severity = "HIGH"

            signal = StandardSignal(
                source="sia",
                event_type="sia.intent_detected",
                severity=severity,
                data={
                    "entity_id": entity_id,
                    "phase": intent.current_phase.name,
                    "confidence": intent.current_confidence,
                    "risk_score": risk_score,
                    "attack_progress": intent.attack_progress,
                    "mitre_tactic": intent.current_phase.mitre_tactic,
                    "source_ip": entity_id,
                },
            )
            self._signal_callback(signal)
        except Exception as e:
            logger.error("SIA signal emission error: %s", e)

    def _on_sandbox_trigger(self, entity_id: str, belief) -> None:
        """Called when BayesianScorer triggers sandbox."""
        self._stats["sandbox_triggers"] += 1

        if self._sandbox_callback:
            try:
                self._sandbox_callback(entity_id, belief)
            except Exception as e:
                logger.error("SIA sandbox callback error: %s", e)

        if self._signal_callback:
            try:
                from core.aegis.types import StandardSignal
                signal = StandardSignal(
                    source="sia",
                    event_type="sia.sandbox_triggered",
                    severity="CRITICAL",
                    data={
                        "entity_id": entity_id,
                        "risk_score": belief.posterior,
                        "peak_posterior": belief.peak_posterior,
                        "evidence_count": len(belief.evidence),
                        "source_ip": entity_id,
                    },
                )
                self._signal_callback(signal)
            except Exception as e:
                logger.error("SIA sandbox signal error: %s", e)

    # ------------------------------------------------------------------
    # Public Queries
    # ------------------------------------------------------------------

    def get_entity_intent(self, entity_id: str) -> Optional[IntentSequence]:
        """Get current intent for an entity without reprocessing."""
        return self.decoder.decode_intent(entity_id)

    def get_entity_risk(self, entity_id: str) -> float:
        """Get current risk score for an entity."""
        return self.scorer.get_risk_score(entity_id)

    def get_story_graph(self, entity_id: str, depth: int = 1) -> Dict[str, Any]:
        """Get the entity's story graph (subgraph + intent + risk)."""
        subgraph = self.graph.get_subgraph(entity_id, depth)
        intent = self.decoder.decode_intent(entity_id)
        risk = self.scorer.get_risk_score(entity_id)

        return {
            "entity_id": entity_id,
            "subgraph": subgraph,
            "intent": intent.to_dict(),
            "risk_score": risk,
            "embedder_warmed_up": self.embedder.is_warmed_up(),
        }

    def get_high_risk_entities(self, threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Get all entities above risk threshold."""
        beliefs = self.scorer.get_high_risk_entities(threshold)
        results = []
        for b in beliefs:
            intent = self.decoder.decode_intent(b.entity_id)
            results.append({
                "entity_id": b.entity_id,
                "risk_score": b.posterior,
                "phase": intent.current_phase.name,
                "confidence": intent.current_confidence,
            })
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "graph": self.graph.get_stats(),
            "embedder": self.embedder.get_stats(),
            "decoder": self.decoder.get_stats(),
            "scorer": self.scorer.get_stats(),
        }
