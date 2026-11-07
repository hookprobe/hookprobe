"""
Hybrid Inference Router — Fast Path / Slow Path Decision Engine.

Routes threat events between:
  Fast path (< 1ms): QSecBit signature match → immediate verdict
  Local path (~100ms): Edge 0.5B model for ambiguous events
  Slow path (1-5s): Nexus offload for deep LLM reasoning

Decision flow:
    QSecBit confidence >= 0.90  → FAST PATH (local verdict)
    QSecBit confidence >= 0.70  → LOCAL MODEL (if available)
    QSecBit confidence <  0.70  → NEXUS OFFLOAD (slow path)

Tier profiles:
    Sentinel (256MB): No local inference — receive filters from Nexus
    Guardian (1.5GB): Offload to Nexus only
    Fortress  (4GB): Hybrid — QSecBit fast + 0.5B local + Nexus
    Nexus   (16GB+): Full — QSecBit fast + 8B local (no offload needed)

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .verdict import (
    ConfidenceLevel,
    ThreatContext,
    VerdictAction,
    VerdictResult,
    VerdictSource,
    make_allow,
    make_drop,
    make_investigate,
)
from .nexus_offload import NexusOffloader

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Inference Mode
# ------------------------------------------------------------------

class InferenceMode(str, Enum):
    """Tier-appropriate inference mode."""
    NONE = "none"           # Sentinel: no local inference
    OFFLOAD = "offload"     # Guardian: offload all to Nexus
    HYBRID = "hybrid"       # Fortress: local + Nexus
    FULL = "full"           # Nexus: full local reasoning


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

@dataclass
class HybridInferenceConfig:
    """Configuration for the hybrid inference router."""
    mode: InferenceMode = InferenceMode.HYBRID
    fast_path_threshold: float = 0.90     # QSecBit confidence for fast path
    local_model_threshold: float = 0.70   # Confidence for local model
    nexus_timeout_s: float = 10.0         # Max wait for Nexus verdict
    max_events_per_second: int = 1000     # Rate limit
    enable_rag_context: bool = True       # Include streaming RAG context

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "fast_path_threshold": self.fast_path_threshold,
            "local_model_threshold": self.local_model_threshold,
            "nexus_timeout_s": self.nexus_timeout_s,
            "max_events_per_second": self.max_events_per_second,
            "enable_rag_context": self.enable_rag_context,
        }


# Tier presets
TIER_CONFIGS = {
    "sentinel": HybridInferenceConfig(
        mode=InferenceMode.NONE,
        enable_rag_context=False,
    ),
    "guardian": HybridInferenceConfig(
        mode=InferenceMode.OFFLOAD,
        enable_rag_context=False,
    ),
    "fortress": HybridInferenceConfig(
        mode=InferenceMode.HYBRID,
        enable_rag_context=True,
    ),
    "nexus": HybridInferenceConfig(
        mode=InferenceMode.FULL,
        enable_rag_context=True,
    ),
}


# ------------------------------------------------------------------
# Hybrid Inference Router
# ------------------------------------------------------------------

class HybridInferenceRouter:
    """Routes threat events through the appropriate inference path.

    The router checks QSecBit confidence first (fast path), then
    decides whether to use the local model or offload to Nexus.

    Usage:
        router = HybridInferenceRouter(config=TIER_CONFIGS["fortress"])
        verdict = router.route(threat_context)
    """

    def __init__(
        self,
        config: Optional[HybridInferenceConfig] = None,
        offloader: Optional[NexusOffloader] = None,
        local_model: Optional[Callable] = None,
        rag_pipeline: Optional[Any] = None,
        llm_monitor: Optional[Any] = None,
    ):
        """Initialize the router.

        Args:
            config: Inference configuration.
            offloader: NexusOffloader for slow path.
            local_model: Callable that takes ThreatContext → VerdictResult.
            rag_pipeline: StreamingRAGPipeline for context enrichment.
            llm_monitor: LLMMonitor for output safety checking.
        """
        self._config = config or HybridInferenceConfig()
        self._offloader = offloader
        self._local_model = local_model
        self._rag = rag_pipeline
        self._llm_monitor = llm_monitor

        # Rate limiting
        self._event_timestamps: List[float] = []

        # Stats
        self._fast_path_count = 0
        self._local_model_count = 0
        self._nexus_offload_count = 0
        self._fallback_count = 0
        self._total_events = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(self, context: ThreatContext) -> VerdictResult:
        """Route a threat event through the appropriate inference path.

        Args:
            context: The threat context to analyze.

        Returns:
            VerdictResult with action, confidence, and source.
        """
        self._total_events += 1
        start = time.time()

        # Rate limit check
        if not self._check_rate_limit():
            return VerdictResult(
                action=VerdictAction.ALLOW,
                confidence=0.5,
                source=VerdictSource.FALLBACK,
                reasoning="Rate limited — allowing traffic",
                source_ip=context.source_ip,
                latency_ms=0.0,
            )

        # Enrich with RAG context if configured
        if self._config.enable_rag_context and self._rag is not None:
            try:
                query = f"{context.event_type} {context.source_ip}".strip()
                context.rag_context = self._rag.query(query, k=10)
            except Exception as e:
                logger.debug("RAG context enrichment failed: %s", e)

        # Route based on mode
        if self._config.mode == InferenceMode.NONE:
            # Sentinel: fast path only
            verdict = self._fast_path(context)
        elif self._config.mode == InferenceMode.OFFLOAD:
            # Guardian: fast path → Nexus
            verdict = self._fast_path(context)
            if verdict.confidence_level in (ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN):
                verdict = self._nexus_path(context)
        elif self._config.mode == InferenceMode.HYBRID:
            # Fortress: fast path → local model → Nexus
            verdict = self._fast_path(context)
            if verdict.confidence_level == ConfidenceLevel.MEDIUM:
                verdict = self._local_path(context) or verdict
            elif verdict.confidence_level in (ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN):
                verdict = self._local_path(context) or self._nexus_path(context)
        elif self._config.mode == InferenceMode.FULL:
            # Nexus: fast path → local model (no offload needed)
            verdict = self._fast_path(context)
            if verdict.confidence_level != ConfidenceLevel.HIGH:
                verdict = self._local_path(context) or verdict
        else:
            verdict = self._fast_path(context)

        verdict.latency_ms = (time.time() - start) * 1000
        return verdict

    @property
    def config(self) -> HybridInferenceConfig:
        """Get current configuration."""
        return self._config

    def set_local_model(self, model: Callable) -> None:
        """Set or replace the local model callable."""
        self._local_model = model

    def set_offloader(self, offloader: NexusOffloader) -> None:
        """Set or replace the Nexus offloader."""
        self._offloader = offloader

    def set_rag_pipeline(self, pipeline: Any) -> None:
        """Set the streaming RAG pipeline."""
        self._rag = pipeline

    def stats(self) -> Dict[str, Any]:
        """Get routing statistics."""
        return {
            "mode": self._config.mode.value,
            "total_events": self._total_events,
            "fast_path_count": self._fast_path_count,
            "local_model_count": self._local_model_count,
            "nexus_offload_count": self._nexus_offload_count,
            "fallback_count": self._fallback_count,
            "fast_path_ratio": (
                self._fast_path_count / self._total_events
                if self._total_events > 0 else 0.0
            ),
            "config": self._config.to_dict(),
        }

    # ------------------------------------------------------------------
    # Internal: Fast Path (QSecBit)
    # ------------------------------------------------------------------

    def _fast_path(self, context: ThreatContext) -> VerdictResult:
        """QSecBit fast path — signature match, < 1ms."""
        self._fast_path_count += 1

        # Use QSecBit confidence directly
        confidence = context.qsecbit_confidence
        score = context.qsecbit_score

        # High confidence threat
        if confidence >= self._config.fast_path_threshold:
            if score < 0.30:
                return VerdictResult(
                    action=VerdictAction.DROP,
                    confidence=confidence,
                    source=VerdictSource.QSECBIT,
                    reasoning=f"QSecBit RED (score={score:.2f}), high confidence threat",
                    source_ip=context.source_ip,
                    threat_type=context.event_type,
                    severity=context.severity,
                )
            elif score > 0.55:
                return make_allow(
                    confidence=confidence,
                    reasoning=f"QSecBit GREEN (score={score:.2f})",
                    source_ip=context.source_ip,
                )

        # Medium confidence — might need deeper analysis
        if confidence >= self._config.local_model_threshold:
            action = VerdictAction.DROP if score < 0.30 else VerdictAction.INVESTIGATE
            return VerdictResult(
                action=action,
                confidence=confidence,
                source=VerdictSource.QSECBIT,
                reasoning=f"QSecBit AMBER (score={score:.2f}), moderate confidence",
                source_ip=context.source_ip,
                threat_type=context.event_type,
                severity=context.severity,
            )

        # Low confidence — needs more analysis
        return make_investigate(
            confidence=confidence,
            reasoning=f"QSecBit low confidence ({confidence:.2f}), needs deeper analysis",
            source_ip=context.source_ip,
            threat_type=context.event_type,
            severity=context.severity,
        )

    # ------------------------------------------------------------------
    # Internal: Local Model Path
    # ------------------------------------------------------------------

    def _local_path(self, context: ThreatContext) -> Optional[VerdictResult]:
        """Local 0.5B/8B model path — ~100ms."""
        if self._local_model is None:
            return None

        self._local_model_count += 1

        try:
            verdict = self._local_model(context)
            if isinstance(verdict, VerdictResult):
                verdict.source = VerdictSource.LOCAL_MODEL

                # Safety check via LLM monitor
                if self._llm_monitor and verdict.reasoning:
                    safe, alert = self._llm_monitor.check_output(verdict.reasoning)
                    if not safe:
                        logger.warning("LLM monitor blocked local model output")
                        return None

                return verdict
        except Exception as e:
            logger.warning("Local model inference failed: %s", e)

        return None

    # ------------------------------------------------------------------
    # Internal: Nexus Offload Path
    # ------------------------------------------------------------------

    def _nexus_path(self, context: ThreatContext) -> VerdictResult:
        """Nexus offload path — 1-5 seconds."""
        if self._offloader is None:
            self._fallback_count += 1
            return make_investigate(
                confidence=0.3,
                reasoning="No Nexus connection — manual investigation needed",
                source_ip=context.source_ip,
            )

        self._nexus_offload_count += 1

        verdict = self._offloader.offload(context)
        return verdict

    # ------------------------------------------------------------------
    # Internal: Rate Limiting
    # ------------------------------------------------------------------

    def _check_rate_limit(self) -> bool:
        """Check if event rate is within limit."""
        now = time.time()
        # Clean old timestamps (keep last 1 second)
        self._event_timestamps = [
            t for t in self._event_timestamps if now - t < 1.0
        ]
        if len(self._event_timestamps) >= self._config.max_events_per_second:
            return False
        self._event_timestamps.append(now)
        return True


# ------------------------------------------------------------------
# Factory
# ------------------------------------------------------------------

def create_hybrid_router(
    tier: str = "fortress",
    rag_pipeline: Optional[Any] = None,
    nexus_callback: Optional[Callable] = None,
    local_model: Optional[Callable] = None,
    llm_monitor: Optional[Any] = None,
) -> HybridInferenceRouter:
    """Create a tier-appropriate hybrid inference router.

    Args:
        tier: Product tier name (sentinel, guardian, fortress, nexus).
        rag_pipeline: StreamingRAGPipeline for context.
        nexus_callback: Callback simulating Nexus processing.
        local_model: Local model callable.
        llm_monitor: LLMMonitor for output safety.

    Returns:
        Configured HybridInferenceRouter.
    """
    config = TIER_CONFIGS.get(tier, TIER_CONFIGS["fortress"])

    offloader = None
    if config.mode in (InferenceMode.OFFLOAD, InferenceMode.HYBRID):
        offloader = NexusOffloader(
            rag_pipeline=rag_pipeline,
            timeout_s=config.nexus_timeout_s,
            nexus_callback=nexus_callback,
        )

    return HybridInferenceRouter(
        config=config,
        offloader=offloader,
        local_model=local_model,
        rag_pipeline=rag_pipeline,
        llm_monitor=llm_monitor,
    )
