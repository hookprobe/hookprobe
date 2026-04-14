"""
Metacognitive Router — Phase 21

The anterior cingulate cortex analog. The CNO's prior architecture produced
confidence scores on every verdict but never acted on them — a 0.51 verdict
and a 0.99 verdict went through the same code path. This module closes that
gap: uncertain verdicts are routed to deeper analysis and soft-blocked
(QUARANTINE) rather than hard-blocked.

Decision tree:
    conf_distance = |consensus_score - 0.5|

    if conf_distance < 0.15 or silos_agreeing == 0 or novel_flag:
        → DEEP_ANALYSIS route (async LLM + shadow pentester + extended obs)
        → QUARANTINE action (30-min soft-block, auto-expire)
    elif confidence > 0.90 and silos_agreeing >= 2:
        → fast commit (unchanged from prior behavior)
    else:
        → standard path

This implements the ACC's conflict-monitoring → prefrontal-recruitment loop.
When the brain is uncertain or conflict is high, it does NOT commit — it
recruits additional resources. The CNO now does the same.

Author: HookProbe Team
License: Proprietary
Version: 21.0.0
"""

import logging
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# Thresholds (tunable; Phase 23 predictive coder will drift these)
AMBIGUITY_THRESHOLD = 0.15      # |score - 0.5| below this = ambiguous
HIGH_CONFIDENCE = 0.90          # above this = fast-path commit
SOFT_BLOCK_TTL_S = 1800         # 30 min QUARANTINE TTL
MAX_DEEP_ANALYSIS_QUEUE = 50    # backpressure cap

# Histogram bucket edges for confidence distribution (exposed in /status)
_CONF_BUCKETS = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]


class MetacognitiveRouter:
    """Confidence-gated routing for Multi-RAG verdicts.

    Intercepts verdicts after Multi-RAG consensus computes them but
    before action is committed. Classifies into three paths:

        FAST_COMMIT      — high confidence + silo agreement (commits as-is)
        STANDARD         — medium confidence (commits, logs as-is)
        DEEP_ANALYSIS    — ambiguous / novel / silos disagree (quarantines +
                           queues for async deep re-analysis)

    The router does NOT change verdict; it changes the ACTION applied and
    optionally enqueues the verdict for LLM + shadow pentester re-evaluation.
    """

    def __init__(self, on_deep_analysis_requested=None):
        """
        Args:
            on_deep_analysis_requested: Optional callback(verdict_dict) invoked
                when a verdict is routed to DEEP_ANALYSIS. The organism wires
                this to the LLM + shadow pentester path.
        """
        self._on_deep_analysis = on_deep_analysis_requested
        self._lock = threading.Lock()
        self._deep_analysis_queue_depth = 0

        self._stats = {
            'total_routed': 0,
            'fast_commits': 0,
            'standard_path': 0,
            'deep_analysis_queued': 0,
            'deep_analysis_dropped_backpressure': 0,
            'quarantines_issued': 0,
            'ambiguous_verdicts': 0,
            'novel_verdicts': 0,
            'conflict_verdicts': 0,  # silos_agreeing == 0
        }
        # Confidence histogram: 10 buckets 0.0-1.0
        self._conf_histogram = [0] * (len(_CONF_BUCKETS) - 1)

    def route(self, verdict: Dict[str, Any]) -> Dict[str, Any]:
        """Route a verdict through the metacognitive gate.

        Returns a modified verdict dict with:
          - `meta_route` field added ('FAST_COMMIT'|'STANDARD'|'DEEP_ANALYSIS')
          - `action` possibly changed (hard block → QUARANTINE for DEEP_ANALYSIS)
          - `metacognition` sub-dict with reasoning
        """
        with self._lock:
            self._stats['total_routed'] += 1

        consensus_score = float(verdict.get('consensus_score', 0.5))
        confidence = float(verdict.get('confidence', 0.5))
        silos_agreeing = int(verdict.get('silos_agreeing', 0))
        novel_flag = bool(verdict.get('novel_pattern', False)
                          or verdict.get('is_novel', False))
        original_action = verdict.get('action', 'monitor')

        # Update confidence histogram
        self._record_confidence(confidence)

        # Compute ambiguity: how far from decision boundary?
        conf_distance = abs(consensus_score - 0.5)
        is_ambiguous = conf_distance < AMBIGUITY_THRESHOLD
        is_conflict = silos_agreeing == 0

        # Decision tree
        if is_ambiguous or is_conflict or novel_flag:
            route_decision = 'DEEP_ANALYSIS'
            reasons = []
            if is_ambiguous:
                reasons.append(f'ambiguous(Δ={conf_distance:.3f})')
                with self._lock:
                    self._stats['ambiguous_verdicts'] += 1
            if is_conflict:
                reasons.append('silo_conflict')
                with self._lock:
                    self._stats['conflict_verdicts'] += 1
            if novel_flag:
                reasons.append('novel_pattern')
                with self._lock:
                    self._stats['novel_verdicts'] += 1

            new_action = self._downgrade_action(original_action)
            verdict['meta_route'] = route_decision
            verdict['meta_reason'] = ','.join(reasons)
            verdict['original_action'] = original_action
            verdict['action'] = new_action
            verdict['ttl_override_s'] = SOFT_BLOCK_TTL_S

            if new_action == 'quarantine':
                with self._lock:
                    self._stats['quarantines_issued'] += 1

            self._enqueue_deep_analysis(verdict)

        elif confidence > HIGH_CONFIDENCE and silos_agreeing >= 2:
            route_decision = 'FAST_COMMIT'
            verdict['meta_route'] = route_decision
            verdict['meta_reason'] = (
                f'high_confidence({confidence:.2f}) + '
                f'silo_majority({silos_agreeing}/3)'
            )
            with self._lock:
                self._stats['fast_commits'] += 1

        else:
            route_decision = 'STANDARD'
            verdict['meta_route'] = route_decision
            verdict['meta_reason'] = 'default_path'
            with self._lock:
                self._stats['standard_path'] += 1

        verdict['metacognition'] = {
            'route': route_decision,
            'conf_distance': round(conf_distance, 4),
            'confidence': round(confidence, 4),
            'silos_agreeing': silos_agreeing,
            'is_ambiguous': is_ambiguous,
            'is_conflict': is_conflict,
            'is_novel': novel_flag,
        }

        logger.info(
            "META: %s for %s — score=%.3f conf=%.2f silos=%d reason=%s",
            route_decision, verdict.get('src_ip', '?'), consensus_score,
            confidence, silos_agreeing, verdict['meta_reason'],
        )
        return verdict

    def _downgrade_action(self, original: str) -> str:
        """Soft-block mapping for uncertain verdicts.

        Rule: anything that would have been a hard block becomes QUARANTINE;
        investigate stays investigate; monitor stays monitor.
        """
        if original in ('block', 'drop'):
            return 'quarantine'
        return original

    def _enqueue_deep_analysis(self, verdict: Dict[str, Any]) -> None:
        """Fire the callback for deep analysis, with backpressure."""
        with self._lock:
            if self._deep_analysis_queue_depth >= MAX_DEEP_ANALYSIS_QUEUE:
                self._stats['deep_analysis_dropped_backpressure'] += 1
                logger.warning(
                    "META: deep_analysis backpressure — dropping verdict for %s",
                    verdict.get('src_ip', '?'))
                return
            self._deep_analysis_queue_depth += 1
            self._stats['deep_analysis_queued'] += 1

        if self._on_deep_analysis:
            try:
                # Callback is expected to be non-blocking (enqueue only)
                self._on_deep_analysis(verdict)
            except Exception as e:
                logger.error("Deep analysis callback error: %s", e)
            finally:
                with self._lock:
                    self._deep_analysis_queue_depth = max(
                        0, self._deep_analysis_queue_depth - 1)
        else:
            # No callback wired — just decrement (testing / partial integration)
            with self._lock:
                self._deep_analysis_queue_depth = max(
                    0, self._deep_analysis_queue_depth - 1)

    def _record_confidence(self, confidence: float) -> None:
        """Update confidence histogram. Thread-safe."""
        idx = min(int(confidence * 10), 9)
        with self._lock:
            self._conf_histogram[idx] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Return router statistics including confidence histogram."""
        with self._lock:
            histogram_dict = {
                f"{_CONF_BUCKETS[i]:.1f}-{_CONF_BUCKETS[i+1]:.1f}":
                self._conf_histogram[i]
                for i in range(len(self._conf_histogram))
            }
            return {
                **self._stats,
                'confidence_histogram': histogram_dict,
                'deep_analysis_queue_depth': self._deep_analysis_queue_depth,
                'thresholds': {
                    'ambiguity_cutoff': AMBIGUITY_THRESHOLD,
                    'high_confidence': HIGH_CONFIDENCE,
                    'soft_block_ttl_s': SOFT_BLOCK_TTL_S,
                },
            }
