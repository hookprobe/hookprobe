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
import re
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
from .cno_aegis_bridge import CNOAegisBridge

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Validate CH_DB is a safe identifier
if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

HEALTH_PORT = int(os.environ.get('CNO_HEALTH_PORT', '8900'))
BRIDGE_INTERVAL_S = float(os.environ.get('CNO_BRIDGE_INTERVAL', '10'))
BRIDGE_LOOKBACK_S = int(os.environ.get('CNO_BRIDGE_LOOKBACK', '15'))

# Risk velocity thresholds (mirrors cognitive_defense.py)
REFLEX_VELOCITY = float(os.environ.get('REFLEX_VELOCITY', '0.30'))
REASON_VELOCITY = float(os.environ.get('REASON_VELOCITY', '0.10'))

# ============================================================================
# Tier-Aware Component Gating
# ============================================================================

HOOKPROBE_TIER = os.environ.get('HOOKPROBE_TIER', 'fortress').lower()

TIER_CAPABILITIES = {
    'sentinel': set(),  # CNO disabled entirely
    'guardian': {'siem', 'stress', 'controller', 'bridge', 'health',
                 'session', 'aegis_bridge'},
    # Phase 13: added 'federated' + 'fec' to fortress tier. Previously
    # only nexus had federation, but with a single-server deployment,
    # fortress IS the nexus. Federation runs in local-only mode when
    # MSSP_API_URL is unset (builds local Bloom filter, no sharing).
    'fortress': {'siem', 'stress', 'controller', 'bridge', 'health',
                 'session', 'aegis_bridge', 'cognitive_defense', 'multi_rag',
                 'emotion', 'camouflage', 'sia', 'app_tracker', 'npu',
                 'activation', 'topology', 'federated', 'fec'},
    'nexus': {'siem', 'stress', 'controller', 'bridge', 'health',
              'session', 'aegis_bridge', 'cognitive_defense', 'multi_rag',
              'emotion', 'camouflage', 'sia', 'app_tracker', 'npu',
              'activation', 'topology', 'federated', 'fec'},
}


def _has(cap: str) -> bool:
    """Check if current tier has a capability."""
    return cap in TIER_CAPABILITIES.get(HOOKPROBE_TIER, TIER_CAPABILITIES['fortress'])


# ============================================================================
# HYDRA Bridge — Feeds data from existing pipeline into CNO
# ============================================================================

class HYDRABridge:
    """Bridges HYDRA ClickHouse data into the CNO nervous system.

    Polls ClickHouse for recent verdicts, risk velocities, and flow
    metadata, then injects them as SynapticEvents and PacketSnapshots.
    """

    def __init__(self, controller: SynapticController, siem: PacketSIEM,
                 sia_active: bool = False):
        self._controller = controller
        self._siem = siem
        self._sia_active = sia_active  # Phase 11: flag for SIA routing
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

            # Synthesize a token narrative from verdict data so the
            # psychology silo (Silo 3) has TTP patterns to match against.
            # Without this, the silo always returns score=0.
            token_parts = []
            if score >= 0.8:
                token_parts.append('HIGH_ENTROPY')
            if verdict == 'malicious':
                token_parts.append('KNOWN_BAD')
            if action == 'block':
                token_parts.append('FLOOD')
            elif action == 'throttle':
                token_parts.append('BURST')
            token_narrative = ' '.join(token_parts)

            payload = {
                'anomaly_score': score,
                'verdict': verdict,
                'action_taken': action,
                'token_narrative': token_narrative,
            }

            self._controller.submit_upward(
                source_layer=BrainLayer.CEREBELLUM,
                route=route,
                event_type=f"hydra.verdict.{verdict}",
                priority=priority,
                source_ip=src_ip,
                payload=payload,
            )

            # Phase 2A: ALSO submit malicious verdicts to Multi-RAG for
            # consensus evaluation.
            if verdict == 'malicious' and route != SynapticRoute.MULTI_RAG:
                self._controller.submit_upward(
                    source_layer=BrainLayer.CEREBELLUM,
                    route=SynapticRoute.MULTI_RAG,
                    event_type="hydra.verdict.rag",
                    priority=3,  # P2 cognitive tier
                    source_ip=src_ip,
                    payload=payload,
                )

            # Phase 11: feed ALL verdicts to Entity Graph for SIA kill-chain
            # attribution. SIA tracks IP→IP connections, detects phase
            # progression (RECON→LATERAL→EXFIL), and triggers sandbox
            # at BayesianScorer threshold (0.92 posterior).
            if self._sia_active:
                self._controller.submit_upward(
                    source_layer=BrainLayer.CEREBELLUM,
                    route=SynapticRoute.ENTITY_GRAPH,
                    event_type=f"hydra.verdict.sia",
                    priority=5,  # P1 somatic — SIA needs all traffic
                    source_ip=src_ip,
                    payload=payload,
                )

            count += 1

        self._stats['verdicts_bridged'] += count
        return count

    def _bridge_velocities(self) -> int:
        """Bridge risk velocities — route high-velocity IPs to Cognitive Defense."""
        query = (
            f"SELECT src_ip, risk_velocity, composite_risk, "
            f"kill_chain_state, rag_triggered, "
            f"arrayStringConcat(token_sequence, ' ') AS token_str "
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
            token_str = parts[5] if len(parts) > 5 else ''

            # Catastrophic velocity → Cognitive Defense (Reflex, P1)
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

            # Synthesize narrative from velocity data if token_str is empty
            # L98: correct kill-chain → TTP token mapping (was semantically
            # wrong — lateral_movement→DRIP_FEED conflated different tactics)
            if not token_str:
                vel_parts = []
                if abs(velocity) > REFLEX_VELOCITY:
                    vel_parts.append('ACCELERATING')
                if risk > 0.7:
                    vel_parts.append('KNOWN_BAD')
                if kill_chain == 'lateral_movement':
                    vel_parts.append('LATERAL_MOVEMENT')
                elif kill_chain == 'exfiltration':
                    vel_parts.append('DATA_EXFILTRATION')
                elif kill_chain == 'command_control':
                    vel_parts.append('C2_BEACON')
                elif kill_chain == 'execution':
                    vel_parts.append('DNS_TUNNEL')
                token_str = ' '.join(vel_parts)

            payload = {
                'risk_velocity': velocity,
                'composite_risk': risk,
                'kill_chain_state': kill_chain,
                'rag_triggered': rag_triggered,
                'token_narrative': token_str,
            }

            self._controller.submit_upward(
                source_layer=BrainLayer.CEREBELLUM,
                route=route,
                event_type="velocity.spike",
                priority=priority,
                source_ip=src_ip,
                payload=payload,
            )

            # Alexandria fix: ALSO submit a copy to Multi-RAG at P2 (cognitive)
            # priority. The previous routing was exclusive — events went to
            # CognitiveDefense OR Multi-RAG but never both. Since rag_triggered
            # was always 0, Multi-RAG was permanently starved (0 queries in 8+
            # days). Now every velocity spike above the reason threshold also
            # gets a consensus evaluation. The thalamus P2 40% admission cap
            # prevents flooding — only ~40% of these will be admitted.
            if (route != SynapticRoute.MULTI_RAG
                    and abs(velocity) > REASON_VELOCITY * 0.5):
                self._controller.submit_upward(
                    source_layer=BrainLayer.CEREBELLUM,
                    route=SynapticRoute.MULTI_RAG,
                    event_type="velocity.spike.rag",
                    # Phase 2A: P6→P3. At P6 (informational) the thalamus
                    # dropped 85%+ of these events via the admission cap.
                    # P3 = high-cognitive, matching the original MULTI_RAG
                    # rag_triggered path priority. The P2 40% cap still
                    # applies but P3 is near the somatic admission boundary
                    # so more events get through.
                    priority=3,
                    source_ip=src_ip,
                    payload=payload,
                )

            count += 1

        self._stats['velocities_bridged'] += count
        return count

    def _bridge_flows(self) -> int:
        """Bridge recent NAPSE flows into PacketSIEM working memory."""
        query = (
            f"SELECT src_ip, dst_ip, src_port, dst_port, proto, "
            f"bytes_orig, COALESCE(intent_class, '') AS intent_class, "
            f"toUnixTimestamp(timestamp) "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE timestamp > now() - INTERVAL {BRIDGE_LOOKBACK_S} SECOND "
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
                    timestamp=time.time(),  # Use current time — SIEM is working memory,
                    src_ip=parts[0],        # not a historical record. ClickHouse timestamps
                                            # lag 5+ min due to inspector flush delay.
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
        if HOOKPROBE_TIER == 'sentinel':
            raise SystemExit("CNO disabled on Sentinel tier (insufficient RAM)")

        self._tier = HOOKPROBE_TIER

        # === Always created (Guardian+) ===
        self._siem = PacketSIEM()
        self._stress = StressGauge(on_state_change=self._on_stress_change)
        self._controller = SynapticController()

        # Phase 22: Episodic memory (hippocampus) — opens episode per verdict
        self._episodic_memory = None
        try:
            from .episodic_memory import EpisodicMemory
            self._episodic_memory = EpisodicMemory(
                on_episode_closed=self._on_episode_closed)
            logger.info("Episodic memory enabled (Phase 22)")
        except ImportError:
            pass

        # Phase 24: Global workspace (shared "conscious" state)
        self._workspace = None
        try:
            from .global_workspace import GlobalWorkspace
            self._workspace = GlobalWorkspace()
            logger.info("Global workspace enabled (Phase 24)")
        except ImportError:
            pass

        # Phase 23: Predictive coder + outcome observer
        self._predictive_coder = None
        self._outcome_observer = None
        try:
            from .predictive_coder import PredictiveCoder
            from .outcome_observer import OutcomeObserver
            from . import multi_rag_consensus as _mrc
            # Instantiate predictive coder with refs to consensus module
            psych_silo = None
            # Psychology silo reference is obtained AFTER multi_rag is created
            # (see below — we populate it right after _multi_rag init)
            self._predictive_coder = PredictiveCoder(
                consensus_module=_mrc,
                psychology_silo=None)  # populated after _multi_rag init
            self._outcome_observer = OutcomeObserver(
                emotion_engine=None)  # wired after _emotion init
            logger.info("Predictive coder + outcome observer enabled (Phase 23)")
        except ImportError:
            pass

        # === Tier-gated components ===
        self._multi_rag = (
            MultiRAGConsensus(on_verdict=self._on_rag_verdict_with_episode,
                              npu_bridge=NPUBridge() if _has('npu') else None)
            if _has('multi_rag') else None
        )
        # Phase 23: plug psychology silo reference into predictive coder
        if self._predictive_coder and self._multi_rag:
            for silo in self._multi_rag._silos:
                if silo.name == 'attacker_psychology':
                    self._predictive_coder._psych_silo = silo
                    break
        self._npu = NPUBridge() if _has('npu') else None
        self._emotion = (
            EmotionEngine(on_emotion_change=self._on_emotion_change)
            if _has('emotion') else None
        )
        # Phase 23: plug emotion reference into outcome observer
        if self._outcome_observer and self._emotion:
            self._outcome_observer._emotion = self._emotion
        self._camouflage = (
            AdaptiveCamouflage(bpf_write_callback=self._controller.queue_bpf_write)
            if _has('camouflage') else None
        )
        self._session_analyzer = (
            SessionAnalyzer(submit_event=self._controller.submit_upward)
            if _has('session') else None
        )
        self._app_tracker = (
            AppTracker(submit_event=self._controller.submit_upward)
            if _has('app_tracker') else None
        )
        self._federated = (
            FederatedSync(on_global_update=self._on_federated_update)
            if _has('federated') else None
        )
        self._fec = FECCodec() if _has('fec') else None
        self._activation = ActivationController() if _has('activation') else None
        self._topology = (
            TransportMapper(submit_event=self._controller.submit_upward)
            if _has('topology') else None
        )

        # CNO-AEGIS bridge (connects CNO signal system to AEGIS routing)
        self._aegis_bridge = CNOAegisBridge(self._controller) if _has('aegis_bridge') else None

        # CognitiveDefense + SIA (lazy-initialized in run())
        self._cognitive_defense = None
        self._sia_engine = None

        # HYDRA bridge (always active)
        self._bridge = HYDRABridge(self._controller, self._siem,
                                    sia_active=(self._sia_engine is not None))

        # Health server
        self._health_server = None
        self._health_thread = None

        # Lifecycle
        self._running = False
        self._started_at = 0.0

        active = sum(1 for c in [
            self._siem, self._stress, self._controller, self._multi_rag,
            self._emotion, self._camouflage, self._session_analyzer,
            self._app_tracker, self._federated, self._fec, self._activation,
            self._topology, self._aegis_bridge, self._npu,
        ] if c is not None)
        logger.info("CNO Organism created (tier=%s, %d components)", self._tier, active)

    def _on_stress_change(self, old: StressState, new: StressState,
                          score: float) -> None:
        """Called by StressGauge when stress state transitions.

        Pushes the new state to the BPF flow control map,
        feeds the Emotion Engine, and logs.
        Phase 24: broadcasts new state to global workspace.
        """
        logger.info("ORGANISM STRESS: %s → %s (score=%.3f)",
                     old.value, new.value, score)

        # Phase 24: broadcast to global workspace
        if self._workspace:
            self._workspace.update_stress(new.value)

        # Push to BPF map via Synaptic Controller
        self._controller.submit_downward(
            route=SynapticRoute.XDP_FLOW_CTRL,
            source_ip="",
            action="stress_update",
            priority=1,
            payload={'stress_state': new},
        )

        # Feed stress change to Emotion Engine (if active)
        if self._emotion:
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

    def _on_rag_verdict_with_episode(self, verdict: Dict[str, Any]) -> None:
        """Phase 22 wrapper: open episode THEN run the normal verdict handler.

        Ensures every Multi-RAG verdict becomes a narrative episode that
        Phase 23 can learn from and Phase 25 can replay.
        """
        if self._episodic_memory:
            try:
                self._episodic_memory.open_episode(verdict)
            except Exception as e:
                logger.debug("Episode open error: %s", e)
        self._on_rag_verdict(verdict)

    def _query_packet_rate(self, src_ip: str, since_ts: float,
                            until_ts: float) -> float:
        """Phase 22 helper: query napse_flows for packet rate from an IP.

        Returns packets-per-second between the two timestamps.
        """
        try:
            from .synaptic_controller import (
                CH_DB as _chdb, CH_HOST as _chh, CH_PORT as _chp,
                CH_USER as _chu, CH_PASSWORD as _chpw, _ch_escape
            )
            from urllib.request import Request, urlopen
            query = (
                f"SELECT sum(pkts_orig + pkts_resp) / {max(1, until_ts - since_ts)} AS pps "
                f"FROM {_chdb}.napse_flows "
                f"WHERE src_ip = '{_ch_escape(src_ip)}' "
                f"AND timestamp >= toDateTime64({since_ts}, 3) "
                f"AND timestamp <  toDateTime64({until_ts}, 3) "
                f"FORMAT TSV"
            )
            url = f"http://{_chh}:{_chp}/"
            req = Request(url, data=query.encode('utf-8'))
            req.add_header('X-ClickHouse-User', _chu)
            req.add_header('X-ClickHouse-Key', _chpw)
            req.add_header('X-ClickHouse-Database', _chdb)
            with urlopen(req, timeout=5) as resp:
                val = resp.read().decode('utf-8').strip()
                return float(val) if val else 0.0
        except Exception:
            return 0.0

    def _on_episode_closed(self, episode: Dict[str, Any]) -> None:
        """Phase 22 callback: episode resolved with outcome.

        Phase 23: feeds the closed episode to predictive coder so it
        can drift silo weights + TTP severities.
        """
        logger.info(
            "CNO learned: %s outcome=%s err=%.3f",
            episode.get('src_ip', '?'),
            episode.get('final_outcome', '?'),
            episode.get('prediction_error', 0))

        # Phase 23: delta-rule update on consensus parameters
        if self._predictive_coder:
            try:
                self._predictive_coder.on_episode_closed(episode)
            except Exception as e:
                logger.debug("Predictive coder error: %s", e)

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

        # Feed to Emotion Engine — Phase 2C: malicious verdicts are
        # RESOLVED threats (we identified and can act on them), not new
        # scares. Benign verdicts are calming. This matches the v3 approach
        # where successful defense = positive stimulus.
        if self._emotion:
            if v == 'malicious':
                # We identified a real threat — resolved, not panic
                self._emotion.process_stimulus('threat_resolved', confidence * 0.15, verdict)
            elif v == 'suspicious':
                # Uncertain — slight arousal but not full negative
                self._emotion.process_stimulus('novel_pattern', confidence * 0.05, verdict)
            elif v == 'benign':
                # All clear for this IP — calming
                self._emotion.process_stimulus('all_clear', 0.05, verdict)

        # Route action to Brainstem
        # Phase 21: honor metacognitive router's ttl_override_s for QUARANTINE
        if action == 'block' and ip:
            self._controller.push_to_blocklist(
                ip=ip, ttl_seconds=3600,
                reason=f"Multi-RAG consensus: {v} (confidence={confidence:.2f})",
            )
        elif action == 'quarantine' and ip:
            # Phase 21: soft-block with short TTL; verdict is provisional
            ttl = int(verdict.get('ttl_override_s', 1800))
            meta_reason = verdict.get('meta_reason', 'provisional')
            self._controller.push_to_blocklist(
                ip=ip, ttl_seconds=ttl,
                reason=f"PROVISIONAL:{meta_reason}:{v}(conf={confidence:.2f})",
            )
            logger.info("META QUARANTINE: %s for %ds (reason=%s)",
                         ip, ttl, meta_reason)
        elif action == 'investigate' and ip:
            # Log for analyst review — no automatic block for investigate
            logger.info("RAG INVESTIGATE: %s requires human review", ip)

        # Phase 12: route verdicts to AEGIS agents via the bridge.
        if self._aegis_bridge and v in ('malicious', 'suspicious'):
            event = SynapticEvent(
                source_layer=BrainLayer.CEREBRUM,
                route=SynapticRoute.COGNITIVE_DEFENSE,
                event_type=f"hydra.verdict.{v}",
                priority=2 if v == 'malicious' else 5,
                source_ip=ip,
                payload=verdict,
            )
            responses = self._aegis_bridge.route_to_aegis(event)
            if responses:
                logger.info("AEGIS: %d agent responses for %s", len(responses), ip)

            # Phase 14: feed to Neuro-Kernel for eBPF template matching.
            # KernelOrchestrator checks if the threat matches a known
            # pattern (DDoS, port scan, DNS tunnel, etc.) and deploys
            # a purpose-built eBPF program at NIC level.
            if self._kernel_orchestrator:
                try:
                    signal = self._aegis_bridge.synaptic_to_signal(event)
                    action = self._kernel_orchestrator.handle_signal(signal)
                    if action:
                        logger.info(
                            "NEURO-KERNEL: deployed %s for %s (template=%s)",
                            action.action_type if hasattr(action, 'action_type') else 'program',
                            ip,
                            action.template_name if hasattr(action, 'template_name') else 'unknown',
                        )
                except Exception as e:
                    logger.debug("NEURO-KERNEL signal: %s", e)

            # Phase 14: feed to StreamingRAG for real-time threat context.
            if self._streaming_rag:
                try:
                    from core.aegis.neurokernel.types import SensorEvent, SensorType
                    sensor_event = SensorEvent(
                        sensor_type=SensorType.NAPSE_IDS,
                        source_ip=ip,
                        dest_ip='',
                        event_type=f"verdict.{v}",
                        payload={
                            'score': verdict.get('consensus_score', 0),
                            'action': action,
                            'confidence': confidence,
                        },
                    )
                    self._streaming_rag.ingest(sensor_event)
                except Exception as e:
                    logger.debug("StreamingRAG ingest: %s", e)

    def _on_federated_update(self, bloom_stats: Dict[str, Any]) -> None:
        """Called by FederatedSync when global threat view changes.

        Phase 18: logs reputation metrics alongside bloom stats.
        """
        rep = bloom_stats.get('reputation', {})
        logger.info(
            "FEDERATED: %d peers, density=%.3f, trusted=%d/%d, "
            "bft_pass=%d, bft_fail=%d",
            bloom_stats.get('peer_count', 0),
            bloom_stats.get('global_density', 0),
            sum(1 for p in rep.get('peers', {}).values()
                if p.get('trust', 0) >= 0.15),
            rep.get('peer_count', 0),
            rep.get('bft_votes_passed', 0),
            rep.get('bft_votes_failed', 0),
        )

    def _on_zero_day_detected(self, candidate: Dict[str, Any]) -> None:
        """Called by ZeroDayDetector when a novel pattern is found.

        Phase 19: Routes the candidate to the organism's consciousness:
        - Logs the detection with hypothesis
        - Emits a 'novel_pattern' stimulus to the emotion engine
        - Submits a COGNITIVE event to the synaptic controller
        - Persists to ClickHouse for XAI audit trail
        """
        ip = candidate.get('source_ip', 'unknown')
        novelty = candidate.get('novelty_score', 0)
        hypothesis = candidate.get('hypothesis', '')

        logger.warning(
            "ZERO-DAY CANDIDATE: %s (novelty=%.2f, type=%s) — %s",
            ip, novelty, candidate.get('event_type', '?'),
            hypothesis[:200] if hypothesis else candidate.get('summary', '')[:200])

        # Phase 24: flag novel pattern in global workspace (silos will boost
        # APT-category TTPs on next query)
        if self._workspace:
            self._workspace.flag_novel_pattern()

        # Emotion: novel_pattern = mild arousal (VIGILANT, not FEARFUL)
        if self._emotion:
            self._emotion.process_stimulus(
                'novel_pattern', intensity=min(0.3, novelty * 0.5))

        # Synaptic: submit as COGNITIVE event for further analysis
        # BUG FIX (L96): Use BrainLayer/SynapticRoute enums, not strings.
        # And the kwarg is 'payload', not 'data' — prior version silently
        # dropped the payload, so every zero-day event routed with empty data.
        if self._controller:
            self._controller.submit_upward(
                source_layer=BrainLayer.CEREBRUM,
                route=SynapticRoute.COGNITIVE_DEFENSE,
                event_type='zero_day_candidate',
                priority=5,  # SOMATIC tier — important but not reflex
                source_ip=ip,
                payload={
                    'novelty_score': novelty,
                    'summary': candidate.get('summary', ''),
                    'hypothesis': hypothesis,
                    'event_type': candidate.get('event_type', ''),
                },
            )

        # Phase 20: For high-novelty candidates, attempt self-evolving XDP
        if novelty >= 0.75 and self._kernel_orchestrator:
            try:
                from ..aegis.types import StandardSignal
                signal = StandardSignal(
                    source='zero_day_detector',
                    event_type=candidate.get('event_type', 'novel_pattern'),
                    severity='HIGH',
                    data={
                        'source_ip': ip,
                        'summary': candidate.get('summary', ''),
                        'hypothesis': hypothesis,
                    },
                )
                action = self._kernel_orchestrator.handle_novel_threat(
                    signal, threat_description=hypothesis or
                    candidate.get('summary', ''))
                if action:
                    logger.info(
                        "PHASE 20: Self-evolving XDP deployed for %s (%s)",
                        ip, action.program_id)
            except Exception as e:
                logger.debug("Phase 20 code generation: %s", e)

        # Persist to ClickHouse
        self._log_zero_day_candidate(candidate)

    def _log_zero_day_candidate(self, candidate: Dict[str, Any]) -> None:
        """Persist zero-day candidate to ClickHouse for audit trail."""
        try:
            from .synaptic_controller import _ch_escape, CH_DB, CH_HOST, CH_PORT
            from .synaptic_controller import CH_USER, CH_PASSWORD
            from urllib.request import Request, urlopen

            ip = _ch_escape(candidate.get('source_ip', ''))
            summary = _ch_escape(candidate.get('summary', '')[:500])
            hypothesis = _ch_escape(candidate.get('hypothesis', '')[:1000])
            event_type = _ch_escape(candidate.get('event_type', ''))
            novelty = candidate.get('novelty_score', 0)
            max_sim = candidate.get('max_similarity', 0)

            query = (
                f"INSERT INTO {CH_DB}.cno_zero_day_candidates "
                f"(timestamp, source_ip, event_type, novelty_score, "
                f"max_similarity, summary, hypothesis) VALUES "
                f"(now64(3), '{ip}', '{event_type}', {novelty}, "
                f"{max_sim}, '{summary}', '{hypothesis}')"
            )
            url = f"http://{CH_HOST}:{CH_PORT}/"
            req = Request(url, data=query.encode('utf-8'), method='POST')
            req.add_header('X-ClickHouse-User', CH_USER)
            req.add_header('X-ClickHouse-Key', CH_PASSWORD)
            req.add_header('X-ClickHouse-Database', CH_DB)
            with urlopen(req, timeout=5):
                pass
        except Exception as e:
            logger.debug("Zero-day CH log failed: %s", e)

    def _on_emotion_change(self, old: EmotionState, new: EmotionState,
                           valence: float, arousal: float) -> None:
        """Called by EmotionEngine when emotional state transitions.

        Applies the corresponding camouflage profile.
        Phase 24: broadcasts new state to global workspace.
        """
        logger.info(
            "ORGANISM EMOTION: %s → %s (valence=%.2f, arousal=%.2f)",
            old.value, new.value, valence, arousal,
        )

        # Phase 24: broadcast to global workspace
        if self._workspace:
            self._workspace.update_emotion(new.value, valence, arousal)

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

    def _init_cognitive_defense(self) -> None:
        """Lazy-init CognitiveDefenseLoop (requires HYDRA in sys.path)."""
        if not _has('cognitive_defense'):
            return
        try:
            hydra_path = os.environ.get('HYDRA_PATH',
                                        '/home/ubuntu/hookprobe/core/hydra')
            if hydra_path not in sys.path:
                sys.path.insert(0, hydra_path)
            from cognitive_defense import CognitiveDefenseLoop
            self._cognitive_defense = CognitiveDefenseLoop()
            logger.info("CognitiveDefenseLoop wired (Reflex/Reason/Learn active)")
        except Exception as e:
            logger.warning("CognitiveDefense unavailable: %s", e)

    def _init_sia(self) -> None:
        """Initialize SIA Engine for kill-chain attribution."""
        if not _has('sia'):
            return
        try:
            hookprobe_base = os.environ.get('HOOKPROBE_BASE',
                                            '/home/ubuntu/hookprobe')
            if hookprobe_base not in sys.path:
                sys.path.insert(0, hookprobe_base)
            from core.napse.intelligence.sia_engine import SIAEngine
            self._sia_engine = SIAEngine()

            # Wire SIA signal callback → CNO AEGIS bridge or direct inject
            def _on_sia_signal(signal):
                if self._aegis_bridge:
                    self._aegis_bridge.feed_from_aegis(signal)
                else:
                    self._controller.submit_upward(
                        source_layer=BrainLayer.CEREBRUM,
                        route=SynapticRoute.ENTITY_GRAPH,
                        event_type=getattr(signal, 'event_type', 'sia.intent'),
                        priority=2,
                        source_ip=getattr(signal, 'data', {}).get('source_ip', ''),
                        payload=getattr(signal, 'data', {}),
                    )

            self._sia_engine.set_signal_callback(_on_sia_signal)
            logger.info("SIA Engine wired for kill-chain attribution")
        except Exception as e:
            logger.warning("SIA Engine unavailable: %s", e)

    def _register_cerebrum_handlers(self) -> None:
        """Register Cerebrum processing handlers with the Synaptic Controller."""

        def _handle_cognitive_defense(event: SynapticEvent):
            """Route to CognitiveDefenseLoop (Reflex/Reason/Learn)."""
            if self._cognitive_defense:
                # Build micro-cycle input from event payload
                velocity_result = {
                    'ip': event.source_ip,
                    'risk_velocity': event.payload.get('risk_velocity', 0),
                    'latest_score': event.payload.get(
                        'anomaly_score',
                        event.payload.get('composite_risk', 0.5)),
                }
                rag_ctx = []
                if event.payload.get('rag_triggered'):
                    rag_ctx = [{'ip': event.source_ip,
                                'prompt_context': event.payload.get('rag_context', '')}]
                try:
                    actions = self._cognitive_defense.process_cycle(
                        [velocity_result], rag_ctx
                    )
                    action_count = 0
                    for action in (actions or []):
                        act = action.get('action', 'monitor')
                        ip = action.get('ip', '')
                        ttl = action.get('ttl_seconds', 3600)
                        conf = action.get('confidence', 0.5)
                        reason = action.get('reasoning', act)
                        if act in ('block_ip', 'block_subnet') and ip:
                            self._controller.push_to_blocklist(ip, ttl, reason)
                        if act not in ('monitor', 'ignore'):
                            action_count += 1

                    # Alexandria fix v3: ONE aggregate stimulus per cognitive
                    # cycle instead of one-per-IP. Previous per-IP approach
                    # (4 IPs × scan_detected) overwhelmed emotion recovery.
                    # All successful actions = threat_resolved (positive).
                    # Intensity capped at 0.15 regardless of how many IPs.
                    if self._emotion and action_count > 0:
                        self._emotion.process_stimulus(
                            'threat_resolved',
                            min(0.15, action_count * 0.03),
                            {'actions': action_count},
                        )
                except Exception as e:
                    logger.error("CognitiveDefense cycle error: %s", e)
            else:
                logger.debug(
                    "CEREBRUM[cognitive_defense]: %s from %s (log-only, no loop)",
                    event.event_type, event.source_ip,
                )

        def _handle_multi_rag(event: SynapticEvent):
            """Route to Multi-RAG Consensus engine."""
            if self._multi_rag:
                try:
                    result = self._multi_rag.evaluate(event)
                    if result:
                        verdict = result.get('consensus_verdict', 'unknown')
                        score = result.get('consensus_score', 0)
                        logger.info(
                            "MULTI-RAG verdict: %s (%.2f) for %s [%s]",
                            verdict, score, event.source_ip, event.event_type,
                        )
                    else:
                        logger.debug(
                            "MULTI-RAG: no result for %s (event=%s)",
                            event.source_ip, event.event_type,
                        )
                except Exception as e:
                    logger.error(
                        "Multi-RAG evaluation FAILED for %s: %s",
                        event.source_ip, e, exc_info=True,
                    )
            else:
                logger.debug("CEREBRUM[multi_rag]: not active on %s tier", self._tier)

        def _handle_temporal(event: SynapticEvent):
            """Route to Temporal Memory — track behavioral trends.

            Phase 4: enriched from stub to info logger with context
            extraction. Full temporal drift engine is Phase 5+.
            """
            logger.info("TEMPORAL: %s from %s (verdict=%s)",
                        event.event_type, event.source_ip,
                        event.payload.get('verdict', 'n/a'))

        def _handle_entity_graph(event: SynapticEvent):
            """Route to SIA Engine for kill chain attribution.

            Phase 11: improved from silent call to full logging. The SIA
            engine tracks IP behavioral progression through MITRE ATT&CK
            kill chain phases. When BayesianScorer posterior crosses 0.92,
            the signal callback triggers sandbox/isolation.
            """
            if self._sia_engine and event.source_ip:
                try:
                    result = self._sia_engine.process_entity(event.source_ip)
                    if result:
                        phase = getattr(result, 'current_phase', None)
                        conf = getattr(result, 'current_confidence', 0)
                        risk = getattr(result, 'risk_score', 0)
                        if phase and conf > 0.3:
                            logger.info(
                                "SIA: %s → phase=%s conf=%.2f risk=%.2f",
                                event.source_ip,
                                phase.name if hasattr(phase, 'name') else str(phase),
                                conf, risk,
                            )
                except Exception as e:
                    logger.debug("SIA process_entity: %s", e)
            else:
                logger.debug("CEREBRUM[entity_graph]: %s from %s",
                             event.event_type, event.source_ip)

        def _handle_session_analysis(event: SynapticEvent):
            """Route session analysis findings to CognitiveDefense.

            Phase 4: implemented from stub. Receives session findings
            that were already evaluated by Multi-RAG (session_analyzer
            now routes to MULTI_RAG first, then critical patterns also
            fire to COGNITIVE_DEFENSE). This handler processes the
            COGNITIVE_DEFENSE copy for reflex action.

            Maps session payload fields to CognitiveDefense format
            (which expects risk_velocity + composite_risk).
            """
            pattern = event.payload.get('pattern', event.event_type)
            mitre = event.payload.get('mitre_technique', '')
            flows = event.payload.get('flows', 0)

            logger.info("SESSION FINDING: %s from %s (%s, %d flows)",
                        pattern, event.source_ip, mitre, flows)

            # Build velocity result compatible with CognitiveDefense
            if self._cognitive_defense:
                velocity_result = {
                    'ip': event.source_ip,
                    'risk_velocity': 0.5,  # session findings = moderate risk
                    'latest_score': min(1.0, flows / 100.0),
                }
                rag_ctx = [{
                    'ip': event.source_ip,
                    'prompt_context': f"Session: {pattern} ({mitre})",
                }]
                try:
                    actions = self._cognitive_defense.process_cycle(
                        [velocity_result], rag_ctx
                    )
                    action_count = 0
                    for action in (actions or []):
                        act = action.get('action', 'monitor')
                        ip = action.get('ip', '')
                        if act in ('block_ip', 'block_subnet') and ip:
                            self._controller.push_to_blocklist(
                                ip, 3600,
                                f"Session analysis: {pattern}",
                            )
                            action_count += 1
                    if action_count > 0:
                        logger.info("SESSION→DEFENSE: %d blocks for %s",
                                    action_count, event.source_ip)
                except Exception as e:
                    logger.error("Session→CognitiveDefense error: %s", e)

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
            # Security audit C5 (updated): bind to 0.0.0.0 for dashboard access.
            # OCI VCN security list blocks port 8900 from the internet.
            # Only local containers (dashboard via host.containers.internal)
            # and the host itself can reach this endpoint.
            # Previously 127.0.0.1 which blocked the dashboard container.
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
        logger.info("  COGNITIVE NETWORK ORGANISM v%s", "5.0.0")
        logger.info("  Brainstem:   XDP programs (external)")
        logger.info("  Cerebellum:  PacketSIEM + StressGauge")
        logger.info("  Cerebrum:    SynapticController + handlers")
        logger.info("=" * 60)

        # Register Cerebrum route handlers
        self._register_cerebrum_handlers()

        # Wire CognitiveDefense and SIA (Fortress+ only)
        self._init_cognitive_defense()
        self._init_sia()

        # Phase 11: update bridge's SIA flag AFTER init (bridge is created
        # in __init__ before SIA loads, so sia_active defaults to False)
        if self._sia_engine and self._bridge:
            self._bridge._sia_active = True
            logger.info("BRIDGE: SIA routing enabled (entity_graph events will flow)")

        # Phase 12: Wire AEGIS multi-agent system into the CNO.
        # AegisClient bootstraps the full stack with graceful fallbacks:
        #   SignalFabric → InferenceEngine → SoulConfig → Memory →
        #   AgentRegistry (9 agents) → ToolExecutor (43 tools) →
        #   AegisOrchestrator (72 routing rules) → Bridges → Scheduler
        if self._aegis_bridge and _has('aegis_bridge'):
            try:
                hookprobe_base = os.environ.get('HOOKPROBE_BASE',
                                                '/home/ubuntu/hookprobe')
                if hookprobe_base not in sys.path:
                    sys.path.insert(0, hookprobe_base)
                from core.aegis.client import AegisClient

                aegis = AegisClient()
                if aegis.orchestrator:
                    self._aegis_bridge._orchestrator = aegis.orchestrator
                    agent_count = len(aegis.registry._agents) \
                        if aegis.registry else 0
                    logger.info(
                        "AEGIS: %d agents wired via AegisClient",
                        agent_count)
                else:
                    logger.warning("AEGIS: Client initialized but no orchestrator")
            except Exception as e:
                logger.warning("AEGIS unavailable: %s", e)

        # Phase 14: Wire Neuro-Kernel into the CNO.
        # KernelOrchestrator matches threat signals to eBPF templates and
        # deploys them at kernel level. StreamingRAG ingests sensor events
        # for real-time threat context. Shadow Pentester tests defenses.
        self._kernel_orchestrator = None
        self._streaming_rag = None
        try:
            hookprobe_base = os.environ.get('HOOKPROBE_BASE',
                                            '/home/ubuntu/hookprobe')
            if hookprobe_base not in sys.path:
                sys.path.insert(0, hookprobe_base)
            from core.aegis.neurokernel import (
                KernelOrchestrator, register_orchestrator,
            )
            from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline

            # Phase 19/20: wire LLM for both hypothesis generation and code gen
            llm_fn = None
            try:
                from core.hydra.cognitive_defense import call_openrouter
                llm_fn = lambda sys, user: call_openrouter(
                    prompt=user, system_prompt=sys,
                    max_tokens=300, temperature=0.4)
            except ImportError:
                pass

            # Phase 20: pass LLM to orchestrator for self-evolving XDP programs
            self._kernel_orchestrator = KernelOrchestrator(
                interface='dummy-mirror',
                llm_fn=llm_fn,
            )
            register_orchestrator(self._kernel_orchestrator)

            self._streaming_rag = StreamingRAGPipeline(
                on_zero_day=self._on_zero_day_detected,
                llm_fn=llm_fn,
            )

            logger.info(
                "NEURO-KERNEL: Orchestrator + StreamingRAG + ZeroDayDetector "
                "+ LLMCodeGenerator wired (interface=dummy-mirror, llm=%s)",
                llm_fn is not None)
        except Exception as e:
            logger.warning("NEURO-KERNEL unavailable: %s", e)

        # Start components
        self._siem.start()
        self._stress.start()
        self._controller.start()
        if self._federated:
            self._federated.start()
        self._start_health_server()

        # Activate dormant components progressively (Fortress+ only)
        if self._activation:
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
        EPISODE_RECONCILE_EVERY = 60   # Every 60th cycle (10 min) — Phase 22

        # Main loop: poll HYDRA data and inject into CNO
        while self._running:
            try:
                stats = self._bridge.poll_cycle()

                # Evaluate emotion state each cycle (Fortress+ only)
                emotion_name = 'n/a'
                if self._emotion:
                    emotion, valence, arousal = self._emotion.evaluate()
                    emotion_name = emotion.value

                # Periodic status log
                spatial = self._siem.get_spatial_state()
                stress = self._stress.state

                if stats['verdicts'] > 0 or stats['velocities'] > 0:
                    logger.info(
                        "BRIDGE: verdicts=%d velocities=%d flows=%d | "
                        "STRESS=%s EMOTION=%s | SIEM: %d pkts, %d src_ips, threat=%.1f%%",
                        stats['verdicts'], stats['velocities'], stats['flows'],
                        stress.value, emotion_name,
                        spatial.total_packets, spatial.unique_src_ips,
                        spatial.threat_ratio * 100,
                    )

                # Phase 3: Emotion stimulus balance.
                # Three layers: (1) spatial threat detection for genuine attacks,
                # (2) high_activity for sustained defense workload, (3) all_clear
                # ONLY when both spatial and verdict bridge are quiet.
                if self._emotion:
                    verdict_count = stats.get('verdicts', 0)

                    # Layer 1: spatial attack detection (genuine network attack)
                    if spatial.is_under_attack and spatial.threat_ratio > 0.20:
                        dominant = spatial.dominant_threat
                        if dominant in ('ddos', 'bruteforce'):
                            self._emotion.process_stimulus('ddos_detected', spatial.threat_ratio)
                        elif dominant == 'scan':
                            self._emotion.process_stimulus('scan_detected', spatial.threat_ratio)
                        elif dominant == 'exfiltration':
                            self._emotion.process_stimulus('exfiltration_detected', spatial.threat_ratio)
                        else:
                            self._emotion.process_stimulus('threat_detected', spatial.threat_ratio)

                    # Layer 2: high verdict activity → vigilant arousal.
                    # If the bridge processed >10 verdicts this cycle, the
                    # organism is under sustained load. Emit a mild arousal
                    # stimulus so it reaches VIGILANT instead of staying
                    # permanently SERENE during 50K verdicts/hour.
                    elif verdict_count > 10:
                        activity_intensity = min(1.0, verdict_count / 50.0)
                        self._emotion.process_stimulus('high_activity', activity_intensity)

                    # Layer 3: all_clear ONLY when both spatial is quiet AND
                    # the verdict bridge processed few/no threats this cycle.
                    # Previously all_clear fired every cycle even during 50K
                    # malicious verdicts because spatial.threat_ratio was 0.
                    elif spatial.threat_ratio < 0.05 and verdict_count <= 5:
                        calm_strength = max(0.05, (0.05 - spatial.threat_ratio) / 0.05)
                        self._emotion.process_stimulus('all_clear', calm_strength)

                # Periodic session analysis (every 30s)
                session_cycle_count += 1
                if self._session_analyzer and session_cycle_count % SESSION_ANALYZE_EVERY == 0:
                    session_findings = self._session_analyzer.analyze_cycle()
                    if any(v > 0 for v in session_findings.values()):
                        logger.info("SESSION: %s", session_findings)

                # Periodic app deviation analysis (every 60s)
                if self._app_tracker and session_cycle_count % APP_ANALYZE_EVERY == 0:
                    app_findings = self._app_tracker.analyze_cycle()
                    if any(v > 0 for v in app_findings.values()):
                        logger.info("APP TRACKER: %s", app_findings)

                # Phase 24: tick global workspace (TTL expiry + persist)
                if self._workspace:
                    try:
                        self._workspace.tick()
                    except Exception as e:
                        logger.debug("Workspace tick error: %s", e)

                # Phase 22: periodic episode reconciliation (every 10 min)
                if (self._episodic_memory
                        and session_cycle_count % EPISODE_RECONCILE_EVERY == 0):
                    try:
                        closed = self._episodic_memory.reconcile_pending(
                            napse_flows_query_fn=self._query_packet_rate)
                        if closed > 0:
                            logger.info("EPISODE RECONCILE: closed %d episodes",
                                        closed)
                    except Exception as e:
                        logger.debug("Episode reconcile error: %s", e)

                # Phase 23a: observe outcomes of recent blocks (every 10 min)
                if (self._outcome_observer
                        and session_cycle_count % EPISODE_RECONCILE_EVERY == 0):
                    try:
                        self._outcome_observer.observe_recent_blocks()
                    except Exception as e:
                        logger.debug("Outcome observer error: %s", e)

                # Periodic topology rebuild (every 5 min)
                if self._topology and session_cycle_count % TOPOLOGY_EVERY == 0:
                    topo = self._topology.rebuild_topology()
                    if topo.get('new_nodes', 0) > 0:
                        logger.info("TOPOLOGY: %s", topo)

                # Periodic activation health check (every 10 min)
                if self._activation and session_cycle_count % HEALTH_CHECK_EVERY == 0:
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

        if self._federated:
            self._federated.stop()
        if self._multi_rag:
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
                'tier': self._tier,
                'cognitive_defense': self._cognitive_defense is not None,
                'sia_engine': self._sia_engine is not None,
            },
            'brainstem': {
                'note': 'XDP programs managed externally (setup-vrf.sh)',
                'camouflage': self._camouflage.get_status() if self._camouflage else None,
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
                'multi_rag': self._multi_rag.get_stats() if self._multi_rag else None,
                'emotion': self._emotion.get_status() if self._emotion else None,
                'session_analyzer': self._session_analyzer.get_stats() if self._session_analyzer else None,
                'app_tracker': self._app_tracker.get_stats() if self._app_tracker else None,
                'aegis_bridge': self._aegis_bridge.get_stats() if self._aegis_bridge else None,
            },
            'federation': self._federated.get_stats() if self._federated else None,
            'npu': self._npu.get_stats() if self._npu else None,
            'fec': self._fec.get_stats() if self._fec else None,
            'topology': self._topology.get_summary() if self._topology else None,
            'activation': self._activation.get_status() if self._activation else None,
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
