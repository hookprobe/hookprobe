#!/usr/bin/env python3
"""
CNO Organism — Main Entry Point (The 15th Container)

The Cognitive Network Organism orchestrator. A single Python process
that wires together the three biological layers:

    Brainstem:   XDP programs + BPF maps (kernel, managed externally)
    Cerebellum:  PacketSIEM (working memory) + StressGauge (hypothalamus)
    Cerebrum:    SynapticController (thalamus) routes to cognitive engines

This process:
    1. Starts the PacketSIEM (60s in-memory sliding window)
    2. Starts the StressGauge (5s polling of XDP/AEGIS/CPU metrics)
    3. Starts the SynapticController (event routing between layers)
    4. Bridges existing HYDRA/NAPSE/AEGIS data into the CNO
    5. Exposes a health endpoint for container orchestration

Threading model:
    Main thread:    HYDRA bridge polling loop (10s cycle)
    Thread 1:       SynapticController dispatch (100ms cycle)
    Thread 2:       StressGauge evaluation (5s cycle)
    Thread 3:       PacketSIEM GC (5s cycle)
    Thread 4:       Health HTTP server (port 8900)

Usage:
    python3 -u cno_organism.py

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import http.server
import json
import logging
import os
import signal
import socketserver
import sys
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

# CNO components
from .types import (
    BrainLayer,
    EmotionState,
    PacketSnapshot,
    StressState,
    SynapticEvent,
    SynapticRoute,
)
from .synaptic_controller import SynapticController
from .stress_gauge import StressGauge
from .packet_siem import PacketSIEM
from .multi_rag_consensus import MultiRAGConsensus
from .emotion_engine import EmotionEngine
from .adaptive_camouflage import AdaptiveCamouflage
from .session_analyzer import SessionAnalyzer
from .app_tracker import AppTracker
from .federated_sync import FederatedSync
from .npu_bridge import NPUBridge
from .fec_codec import FECCodec
from .activation import ActivationController
from .transport_mapper import TransportMapper

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

HEALTH_PORT = int(os.environ.get('CNO_HEALTH_PORT', '8900'))
BRIDGE_INTERVAL_S = float(os.environ.get('CNO_BRIDGE_INTERVAL', '10'))
BRIDGE_LOOKBACK_S = int(os.environ.get('CNO_BRIDGE_LOOKBACK', '15'))

# Risk velocity thresholds (mirrors cognitive_defense.py)
REFLEX_VELOCITY = float(os.environ.get('REFLEX_VELOCITY', '0.30'))
REASON_VELOCITY = float(os.environ.get('REASON_VELOCITY', '0.10'))


# ============================================================================
# HYDRA Bridge — Feeds data from existing pipeline into CNO
# ============================================================================

class HYDRABridge:
    """Bridges HYDRA ClickHouse data into the CNO nervous system.

    Polls ClickHouse for recent verdicts, risk velocities, and flow
    metadata, then injects them as SynapticEvents and PacketSnapshots.
    """

    def __init__(self, controller: SynapticController, siem: PacketSIEM):
        self._controller = controller
        self._siem = siem
        self._last_poll = time.time()
        self._stats = {
            'verdicts_bridged': 0,
            'velocities_bridged': 0,
            'flows_bridged': 0,
            'errors': 0,
        }

    def poll_cycle(self) -> Dict[str, int]:
        """Execute one bridge polling cycle.

        Queries ClickHouse for recent data and injects into CNO.
        Returns counts of bridged items.
        """
        cycle_stats = {'verdicts': 0, 'velocities': 0, 'flows': 0}

        try:
            cycle_stats['verdicts'] = self._bridge_verdicts()
            cycle_stats['velocities'] = self._bridge_velocities()
            cycle_stats['flows'] = self._bridge_flows()
        except Exception as e:
            logger.error("Bridge cycle error: %s", e)
            self._stats['errors'] += 1

        self._last_poll = time.time()
        return cycle_stats

    def _bridge_verdicts(self) -> int:
        """Bridge recent HYDRA verdicts into Synaptic Controller."""
        query = (
            f"SELECT src_ip, anomaly_score, verdict, action_taken "
            f"FROM {CH_DB}.hydra_verdicts "
            f"WHERE timestamp > now() - INTERVAL {BRIDGE_LOOKBACK_S} SECOND "
            f"AND verdict IN ('suspicious', 'malicious') "
            f"ORDER BY anomaly_score DESC "
            f"LIMIT 50"
        )
        result = _ch_query(query)
        if not result:
            return 0

        count = 0
        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 4:
                continue

            src_ip = parts[0]
            score = float(parts[1] or 0)
            verdict = parts[2]
            action = parts[3]

            # Route based on severity
            if score >= 0.95:
                route = SynapticRoute.COGNITIVE_DEFENSE
                priority = 1
            elif verdict == 'malicious':
                route = SynapticRoute.COGNITIVE_DEFENSE
                priority = 2
            else:
                route = SynapticRoute.TEMPORAL_MEMORY
                priority = 5

            self._controller.submit_upward(
                source_layer=BrainLayer.CEREBELLUM,
                route=route,
                event_type=f"hydra.verdict.{verdict}",
                priority=priority,
                source_ip=src_ip,
                payload={
                    'anomaly_score': score,
                    'verdict': verdict,
                    'action_taken': action,
                },
            )
            count += 1

        self._stats['verdicts_bridged'] += count
        return count

    def _bridge_velocities(self) -> int:
        """Bridge risk velocities — route high-velocity IPs to Cognitive Defense."""
        query = (
            f"SELECT src_ip, risk_velocity, composite_risk, "
            f"kill_chain_state, rag_triggered "
            f"FROM {CH_DB}.ip_risk_scores "
            f"WHERE timestamp > now() - INTERVAL {BRIDGE_LOOKBACK_S} SECOND "
            f"AND abs(risk_velocity) > {REASON_VELOCITY} "
            f"ORDER BY abs(risk_velocity) DESC "
            f"LIMIT 20"
        )
        result = _ch_query(query)
        if not result:
            return 0

        count = 0
        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 5:
                continue

            src_ip = parts[0]
            velocity = float(parts[1] or 0)
            risk = float(parts[2] or 0)
            kill_chain = parts[3]
            rag_triggered = int(parts[4] or 0)

            # Catastrophic velocity → Cognitive Defense (Reflex)
            if abs(velocity) > REFLEX_VELOCITY:
                route = SynapticRoute.COGNITIVE_DEFENSE
                priority = 1
            # Elevated velocity → Multi-RAG if RAG was triggered
            elif rag_triggered:
                route = SynapticRoute.MULTI_RAG
                priority = 3
            else:
                route = SynapticRoute.COGNITIVE_DEFENSE
                priority = 4

            self._controller.submit_upward(
                source_layer=BrainLayer.CEREBELLUM,
                route=route,
                event_type="velocity.spike",
                priority=priority,
                source_ip=src_ip,
                payload={
                    'risk_velocity': velocity,
                    'composite_risk': risk,
                    'kill_chain_state': kill_chain,
                    'rag_triggered': rag_triggered,
                },
            )
            count += 1

        self._stats['velocities_bridged'] += count
        return count

    def _bridge_flows(self) -> int:
        """Bridge recent NAPSE flows into PacketSIEM working memory."""
        query = (
            f"SELECT src_ip, dst_ip, src_port, dst_port, proto, "
            f"bytes_orig, intent_class, toUnixTimestamp(start_time) "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE start_time > now() - INTERVAL {BRIDGE_LOOKBACK_S} SECOND "
            f"LIMIT 500"
        )
        result = _ch_query(query)
        if not result:
            return 0

        count = 0
        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 8:
                continue

            try:
                snapshot = PacketSnapshot(
                    timestamp=float(parts[7] or time.time()),
                    src_ip=parts[0],
                    dst_ip=parts[1],
                    src_port=int(parts[2] or 0),
                    dst_port=int(parts[3] or 0),
                    proto=int(parts[4] or 6),
                    bytes_len=int(parts[5] or 0),
                    intent_class=parts[6] or 'benign',
                )
                self._siem.ingest(snapshot)
                count += 1
            except (ValueError, IndexError):
                continue

        self._stats['flows_bridged'] += count
        return count

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, 'last_poll': self._last_poll}


# ============================================================================
# Health HTTP Server
# ============================================================================

class HealthHandler(http.server.BaseHTTPRequestHandler):
    """Minimal health endpoint for container orchestration."""

    organism = None  # Set by CNOOrganism before starting

    def do_GET(self):
        if self.path == '/health':
            status = self.organism.get_health() if self.organism else {}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(status).encode())
        elif self.path == '/status':
            status = self.organism.get_full_status() if self.organism else {}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(status, default=str).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress access logs


# ============================================================================
# CNO Organism — Main Orchestrator
# ============================================================================

class CNOOrganism:
    """The living organism — wires all components and runs the main loop."""

    def __init__(self):
        # Cerebellum components
        self._siem = PacketSIEM()
        self._stress = StressGauge(on_state_change=self._on_stress_change)

        # Thalamus (spans all layers)
        self._controller = SynapticController()

        # Cerebrum: Multi-RAG Consensus (cortex)
        self._multi_rag = MultiRAGConsensus(on_verdict=self._on_rag_verdict)

        # Cerebrum: Emotion Engine (amygdala)
        self._emotion = EmotionEngine(on_emotion_change=self._on_emotion_change)

        # Cerebrum: Adaptive Camouflage (deception system)
        self._camouflage = AdaptiveCamouflage(
            bpf_write_callback=self._controller.queue_bpf_write
        )

        # Cerebrum: Session Analyzer (Wernicke's area)
        self._session_analyzer = SessionAnalyzer(
            submit_event=self._controller.submit_upward
        )

        # Cerebellum: App Tracker (motor cortex)
        self._app_tracker = AppTracker(
            submit_event=self._controller.submit_upward
        )

        # Phase 4: Federated Intelligence
        self._federated = FederatedSync(on_global_update=self._on_federated_update)

        # Phase 4: NPU acceleration bridge
        self._npu = NPUBridge()

        # Phase 4: FEC codec for mesh transport
        self._fec = FECCodec()

        # Phase 5: Activation controller (dormant component lifecycle)
        self._activation = ActivationController()

        # Phase 5: Transport mapper (network topology)
        self._topology = TransportMapper(submit_event=self._controller.submit_upward)

        # HYDRA bridge (feeds existing pipeline data)
        self._bridge = HYDRABridge(self._controller, self._siem)

        # Health server
        self._health_server = None
        self._health_thread = None

        # Lifecycle
        self._running = False
        self._started_at = 0.0

        logger.info("CNO Organism created")

    def _on_stress_change(self, old: StressState, new: StressState,
                          score: float) -> None:
        """Called by StressGauge when stress state transitions.

        Pushes the new state to the BPF flow control map,
        feeds the Emotion Engine, and logs.
        """
        logger.info("ORGANISM STRESS: %s → %s (score=%.3f)",
                     old.value, new.value, score)

        # Push to BPF map via Synaptic Controller
        self._controller.submit_downward(
            route=SynapticRoute.XDP_FLOW_CTRL,
            source_ip="",
            action="stress_update",
            priority=1,
            payload={'stress_state': new},
        )

        # Feed stress change to Emotion Engine
        self._emotion.process_stimulus('stress_change', score, {
            'stress_state': new,
        })

        # If entering FIGHT, also push high-risk IPs to blocklist
        if new == StressState.FIGHT:
            spatial = self._siem.get_spatial_state()
            if spatial.is_under_attack:
                anomalous = self._siem.get_anomalous_ips(threshold_pps=500)
                for entry in anomalous[:5]:  # Block top 5 offenders
                    self._controller.push_to_blocklist(
                        ip=entry['ip'],
                        ttl_seconds=1800,
                        reason=f"FIGHT mode auto-block: {entry['pps']:.0f} pps",
                    )

    def _on_rag_verdict(self, verdict: Dict[str, Any]) -> None:
        """Called by MultiRAGConsensus when a consensus verdict is reached.

        Routes the verdict to the appropriate Brainstem feedback.
        """
        action = verdict.get('action', 'monitor')
        ip = verdict.get('src_ip', '')
        confidence = verdict.get('confidence', 0)
        v = verdict.get('verdict', 'benign')

        logger.info(
            "RAG CONSENSUS: %s → %s (action=%s, confidence=%.2f, silos=%d/3)",
            ip, v, action, confidence, verdict.get('silos_agreeing', 0),
        )

        # Feed to Emotion Engine
        if v == 'malicious':
            self._emotion.process_stimulus('threat_detected', confidence, verdict)
        elif v == 'suspicious':
            self._emotion.process_stimulus('novel_pattern', confidence * 0.6, verdict)

        # Route action to Brainstem
        if action == 'block_ip' and ip:
            self._controller.push_to_blocklist(
                ip=ip, ttl_seconds=3600,
                reason=f"Multi-RAG consensus: {v} (confidence={confidence:.2f})",
            )
        elif action == 'throttle' and ip:
            self._controller.submit_downward(
                route=SynapticRoute.XDP_BLOCKLIST,
                source_ip=ip, action='throttle',
                ttl_seconds=1800,
                reason=f"Multi-RAG throttle: {v}",
            )

    def _on_federated_update(self, bloom_stats: Dict[str, Any]) -> None:
        """Called by FederatedSync when global threat view changes."""
        logger.info("FEDERATED: global view updated — %d peers, density=%.3f",
                     bloom_stats.get('peer_count', 0),
                     bloom_stats.get('global_density', 0))

    def _on_emotion_change(self, old: EmotionState, new: EmotionState,
                           valence: float, arousal: float) -> None:
        """Called by EmotionEngine when emotional state transitions.

        Applies the corresponding camouflage profile.
        """
        logger.info(
            "ORGANISM EMOTION: %s → %s (valence=%.2f, arousal=%.2f)",
            old.value, new.value, valence, arousal,
        )

        # Get camouflage profile and apply
        profile = self._emotion.get_camouflage_profile()
        self._camouflage.apply_profile(new, profile)

        # Push camouflage state to BPF
        self._controller.submit_downward(
            route=SynapticRoute.XDP_CAMOUFLAGE,
            source_ip="",
            action="camouflage_update",
            priority=2,
            payload={
                'emotion': new.value,
                'level': profile['level'],
                'techniques': profile['techniques'],
            },
        )

    def _register_cerebrum_handlers(self) -> None:
        """Register Cerebrum processing handlers with the Synaptic Controller.

        Phase 1: Log-only handlers. Phase 2+ will wire to actual engines.
        """
        def _handle_cognitive_defense(event: SynapticEvent):
            """Route to existing cognitive_defense.py (Reflex/Reason/Learn)."""
            logger.info(
                "CEREBRUM[cognitive_defense]: %s from %s (pri=%d, score=%s)",
                event.event_type, event.source_ip, event.priority,
                event.payload.get('anomaly_score', '?'),
            )
            # Phase 2: Call CognitiveDefenseLoop.process() directly

        def _handle_multi_rag(event: SynapticEvent):
            """Route to Multi-RAG Consensus engine."""
            logger.info(
                "CEREBRUM[multi_rag]: %s from %s (velocity=%s)",
                event.event_type, event.source_ip,
                event.payload.get('risk_velocity', '?'),
            )
            try:
                self._multi_rag.evaluate(event)
            except Exception as e:
                logger.error("Multi-RAG evaluation failed: %s", e)

        def _handle_temporal(event: SynapticEvent):
            """Route to Temporal Memory engine."""
            logger.debug(
                "CEREBRUM[temporal]: %s from %s",
                event.event_type, event.source_ip,
            )

        def _handle_entity_graph(event: SynapticEvent):
            """Route to Entity Graph / SIA engine (Phase 2)."""
            logger.debug(
                "CEREBRUM[entity_graph]: %s from %s",
                event.event_type, event.source_ip,
            )

        def _handle_session_analysis(event: SynapticEvent):
            """Route to Session Analyzer (Wernicke's area)."""
            logger.debug(
                "CEREBRUM[session_analysis]: %s from %s",
                event.event_type, event.source_ip,
            )
            # Session analysis is primarily driven by the periodic cycle,
            # but individual events can trigger focused analysis here.

        self._controller.register_handler(
            SynapticRoute.COGNITIVE_DEFENSE, _handle_cognitive_defense)
        self._controller.register_handler(
            SynapticRoute.MULTI_RAG, _handle_multi_rag)
        self._controller.register_handler(
            SynapticRoute.TEMPORAL_MEMORY, _handle_temporal)
        self._controller.register_handler(
            SynapticRoute.ENTITY_GRAPH, _handle_entity_graph)
        self._controller.register_handler(
            SynapticRoute.SESSION_ANALYSIS, _handle_session_analysis)

    def _start_health_server(self) -> None:
        """Start the health HTTP endpoint."""
        HealthHandler.organism = self
        try:
            socketserver.TCPServer.allow_reuse_address = True
            self._health_server = socketserver.TCPServer(
                ('0.0.0.0', HEALTH_PORT), HealthHandler)
            self._health_thread = threading.Thread(
                target=self._health_server.serve_forever, daemon=True,
                name="cno-health")
            self._health_thread.start()
            logger.info("Health endpoint listening on :%d", HEALTH_PORT)
        except Exception as e:
            logger.error("Failed to start health server: %s", e)

    # ------------------------------------------------------------------
    # Main Loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start all components and run the main bridge loop."""
        self._running = True
        self._started_at = time.time()

        logger.info("=" * 60)
        logger.info("  COGNITIVE NETWORK ORGANISM v%s", "1.0.0")
        logger.info("  Brainstem:   XDP programs (external)")
        logger.info("  Cerebellum:  PacketSIEM + StressGauge")
        logger.info("  Cerebrum:    SynapticController + handlers")
        logger.info("=" * 60)

        # Register Cerebrum route handlers
        self._register_cerebrum_handlers()

        # Start components
        self._siem.start()
        self._stress.start()
        self._controller.start()
        self._federated.start()
        self._start_health_server()

        # Activate dormant components progressively
        activation_results = self._activation.activate_all()
        active = sum(1 for v in activation_results.values() if v)
        logger.info("Activation: %d/%d components activated",
                     active, len(activation_results))

        logger.info("All CNO components started. Entering main bridge loop.")

        # Cycle counters for periodic analysis
        session_cycle_count = 0
        SESSION_ANALYZE_EVERY = 3  # Every 3rd bridge cycle (30s at 10s interval)
        APP_ANALYZE_EVERY = 6      # Every 6th bridge cycle (60s at 10s interval)
        TOPOLOGY_EVERY = 30        # Every 30th cycle (5 min at 10s interval)
        HEALTH_CHECK_EVERY = 60    # Every 60th cycle (10 min at 10s interval)

        # Main loop: poll HYDRA data and inject into CNO
        while self._running:
            try:
                stats = self._bridge.poll_cycle()

                # Evaluate emotion state each cycle
                emotion, valence, arousal = self._emotion.evaluate()

                # Periodic status log
                spatial = self._siem.get_spatial_state()
                stress = self._stress.state

                if stats['verdicts'] > 0 or stats['velocities'] > 0:
                    logger.info(
                        "BRIDGE: verdicts=%d velocities=%d flows=%d | "
                        "STRESS=%s EMOTION=%s | SIEM: %d pkts, %d src_ips, threat=%.1f%%",
                        stats['verdicts'], stats['velocities'], stats['flows'],
                        stress.value, emotion.value,
                        spatial.total_packets, spatial.unique_src_ips,
                        spatial.threat_ratio * 100,
                    )

                # Feed spatial awareness anomalies to emotion engine
                if spatial.is_under_attack:
                    dominant = spatial.dominant_threat
                    if dominant in ('ddos', 'bruteforce'):
                        self._emotion.process_stimulus('ddos_detected', spatial.threat_ratio)
                    elif dominant == 'scan':
                        self._emotion.process_stimulus('scan_detected', spatial.threat_ratio)
                    elif dominant == 'exfiltration':
                        self._emotion.process_stimulus('exfiltration_detected', spatial.threat_ratio)
                    else:
                        self._emotion.process_stimulus('threat_detected', spatial.threat_ratio)
                elif spatial.threat_ratio < 0.01 and stress == StressState.CALM:
                    self._emotion.process_stimulus('all_clear', 0.1)

                # Periodic session analysis (every 30s)
                session_cycle_count += 1
                if session_cycle_count % SESSION_ANALYZE_EVERY == 0:
                    session_findings = self._session_analyzer.analyze_cycle()
                    if any(v > 0 for v in session_findings.values()):
                        logger.info("SESSION: %s", session_findings)

                # Periodic app deviation analysis (every 60s)
                if session_cycle_count % APP_ANALYZE_EVERY == 0:
                    app_findings = self._app_tracker.analyze_cycle()
                    if any(v > 0 for v in app_findings.values()):
                        logger.info("APP TRACKER: %s", app_findings)

                # Periodic topology rebuild (every 5 min)
                if session_cycle_count % TOPOLOGY_EVERY == 0:
                    topo = self._topology.rebuild_topology()
                    if topo.get('new_nodes', 0) > 0:
                        logger.info("TOPOLOGY: %s", topo)

                # Periodic activation health check (every 10 min)
                if session_cycle_count % HEALTH_CHECK_EVERY == 0:
                    health = self._activation.health_check_all()
                    degraded = [k for k, v in health.items() if v == 'degraded']
                    if degraded:
                        logger.warning("ACTIVATION: degraded components: %s", degraded)

            except Exception as e:
                logger.error("Main loop error: %s", e)

            time.sleep(BRIDGE_INTERVAL_S)

    def stop(self) -> None:
        """Gracefully stop all components."""
        logger.info("Stopping CNO Organism...")
        self._running = False

        self._federated.stop()
        self._multi_rag.shutdown()
        self._controller.stop()
        self._stress.stop()
        self._siem.stop()

        if self._health_server:
            self._health_server.shutdown()

        logger.info("CNO Organism stopped.")

    # ------------------------------------------------------------------
    # Status / Health
    # ------------------------------------------------------------------

    def get_health(self) -> Dict[str, Any]:
        """Minimal health check for container orchestration."""
        return {
            'status': 'healthy' if self._running else 'stopped',
            'stress': self._stress.state.value,
            'uptime_s': round(time.time() - self._started_at, 1),
        }

    def get_full_status(self) -> Dict[str, Any]:
        """Full status dump for dashboard."""
        spatial = self._siem.get_spatial_state()
        return {
            'organism': {
                'status': 'alive' if self._running else 'stopped',
                'uptime_s': round(time.time() - self._started_at, 1),
                'version': '5.0.0',
            },
            'brainstem': {
                'note': 'XDP programs managed externally (setup-vrf.sh)',
                'camouflage': self._camouflage.get_status(),
            },
            'cerebellum': {
                'stress': self._stress.get_status(),
                'siem': self._siem.get_stats(),
                'spatial': {
                    'total_packets': spatial.total_packets,
                    'packets_per_second': spatial.packets_per_second,
                    'unique_src_ips': spatial.unique_src_ips,
                    'unique_flows': spatial.unique_flows,
                    'threat_ratio': spatial.threat_ratio,
                    'is_under_attack': spatial.is_under_attack,
                    'dominant_threat': spatial.dominant_threat,
                },
            },
            'cerebrum': {
                'synaptic': self._controller.get_stats(),
                'multi_rag': self._multi_rag.get_stats(),
                'emotion': self._emotion.get_status(),
                'session_analyzer': self._session_analyzer.get_stats(),
                'app_tracker': self._app_tracker.get_stats(),
            },
            'federation': self._federated.get_stats(),
            'npu': self._npu.get_stats(),
            'fec': self._fec.get_stats(),
            'topology': self._topology.get_summary(),
            'activation': self._activation.get_status(),
            'bridge': self._bridge.get_stats(),
        }


# ============================================================================
# ClickHouse Helper
# ============================================================================

def _ch_query(query: str) -> Optional[str]:
    """Execute a ClickHouse SELECT query."""
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None


# ============================================================================
# Entry Point
# ============================================================================

def main():
    """Entry point for the CNO container."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    organism = CNOOrganism()

    # Graceful shutdown on SIGTERM/SIGINT
    def _shutdown(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        organism.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        organism.run()
    except KeyboardInterrupt:
        organism.stop()


if __name__ == '__main__':
    main()
