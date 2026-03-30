#!/usr/bin/env python3
"""
HookProbe Inference Bridge — Tier-Aware Unified Inference API

Routes inference requests to the optimal backend based on hardware
capabilities and product tier. Supports classification (anomaly detection),
text generation (LLM), and embedding (RAG).

Tier behavior:
  Sentinel:  Rule-based classification only (no ML, no LLM)
  Guardian:  CPU sklearn + optional SmolLM-135M for alert triage
  Fortress:  CPU/NPU sklearn + TinyLlama-1.1B + cloud fallback
  Nexus:     GPU/NPU sklearn + large LLM + cloud fallback

Usage:
    from core.brain.hw_detect import detect_hardware
    from core.brain.inference_bridge import InferenceBridge

    hw = detect_hardware()
    bridge = InferenceBridge(tier='fortress', hw_profile=hw)

    # Anomaly detection (24-dim HYDRA features)
    result = bridge.classify(feature_vector)

    # LLM text generation
    text = bridge.generate("Analyze this security event: ...")

    # RAG embedding
    vector = bridge.embed("network intrusion detection")
"""

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from core.brain.hw_detect import HardwareProfile, AcceleratorType, detect_hardware

logger = logging.getLogger(__name__)

# Feature dimensions for the two inference pipelines
HYDRA_FEATURE_DIMS = 24   # Aggregated IP behavioral features (5-min windows)
NAPSE_FEATURE_DIMS = 32   # Per-packet real-time features (ring buffer)


@dataclass
class ClassifyResult:
    """Result from anomaly classification."""
    score: float           # 0.0 (benign) to 1.0 (malicious)
    label: str             # 'benign', 'suspicious', 'malicious'
    backend: str           # Which engine was used
    latency_ms: float      # Inference time


@dataclass
class GenerateResult:
    """Result from text generation."""
    text: str
    backend: str           # 'local_llm', 'cloud', 'template'
    tokens: int
    latency_ms: float


class InferenceBridge:
    """Unified inference API with tier-aware backend selection."""

    def __init__(self, tier: str = "auto", hw_profile: Optional[HardwareProfile] = None):
        self.hw = hw_profile or detect_hardware()
        self.tier = tier if tier != "auto" else self.hw.tier_recommendation
        self._classify_engine = None
        self._llm_engine = None
        self._init_backends()
        logger.info(
            f"InferenceBridge initialized: tier={self.tier}, "
            f"accel={self.hw.accelerator.value}, "
            f"classify={type(self._classify_engine).__name__}, "
            f"llm={'yes' if self._llm_engine else 'no'}"
        )

    def _init_backends(self):
        """Initialize tier-appropriate inference backends."""
        # Classification engine (anomaly detection)
        if self.tier == "sentinel":
            self._classify_engine = _RuleBasedClassifier()
        else:
            # Try NPU engine first, fall back to CPU
            npu_engine = self._try_npu_engine()
            if npu_engine:
                self._classify_engine = npu_engine
            else:
                self._classify_engine = _CPUClassifier()

        # LLM engine (text generation)
        if self.tier in ("guardian", "fortress", "nexus") and self.hw.can_run_llm:
            self._llm_engine = self._try_local_llm()

    def _try_npu_engine(self):
        """Attempt to load NPU-specific classification engine."""
        accel = self.hw.accelerator
        if accel == AcceleratorType.CPU_ONLY:
            return None

        # Import engine dynamically based on detected hardware
        engine_map = {
            AcceleratorType.HAILO_8:    "core.brain.engines.hailo_engine",
            AcceleratorType.HAILO_8L:   "core.brain.engines.hailo_engine",
            AcceleratorType.INTEL_NPU:  "core.brain.engines.openvino_engine",
            AcceleratorType.RK3588_NPU: "core.brain.engines.rknn_engine",
            AcceleratorType.JETSON_ORIN:"core.brain.engines.tensorrt_engine",
            AcceleratorType.APPLE_M4:   "core.brain.engines.coreml_engine",
            AcceleratorType.CORAL_TPU:  "core.brain.engines.litert_engine",
            AcceleratorType.QCS8550:    "core.brain.engines.litert_engine",
            AcceleratorType.QCS6490:    "core.brain.engines.litert_engine",
        }
        module_name = engine_map.get(accel)
        if not module_name:
            return None

        try:
            import importlib
            mod = importlib.import_module(module_name)
            engine = mod.create_engine(self.hw)
            logger.info(f"NPU engine loaded: {accel.value} via {module_name}")
            return engine
        except (ImportError, Exception) as e:
            logger.warning(f"NPU engine {module_name} unavailable: {e}, falling back to CPU")
            return None

    def _try_local_llm(self):
        """Attempt to load local LLM via llama-cpp-python."""
        try:
            from core.brain.engines.llama_engine import LlamaEngine
            model_rec = self.hw.llm_recommendation
            if model_rec == "none":
                return None
            engine = LlamaEngine.from_recommendation(model_rec, self.hw)
            if engine:
                logger.info(f"Local LLM loaded: {model_rec}")
            return engine
        except ImportError:
            logger.info("llama-cpp-python not installed, LLM disabled")
            return None
        except Exception as e:
            logger.warning(f"Local LLM failed to load: {e}")
            return None

    # --- Public API ---

    def classify(self, features: np.ndarray) -> ClassifyResult:
        """Classify a feature vector for anomaly detection.

        Args:
            features: numpy array of shape (n_features,) or (batch, n_features)
                      Expected: 24-dim for HYDRA, 32-dim for NAPSE

        Returns:
            ClassifyResult with score, label, backend, and latency
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        start = time.monotonic()
        try:
            scores = self._classify_engine.score(features)
            latency = (time.monotonic() - start) * 1000

            # Use first score for single-sample case
            score = float(scores[0]) if len(scores) > 0 else 0.5
            if score > 0.7:
                label = "malicious"
            elif score > 0.5:
                label = "suspicious"
            else:
                label = "benign"

            return ClassifyResult(
                score=score, label=label,
                backend=self._classify_engine.name,
                latency_ms=round(latency, 2),
            )
        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return ClassifyResult(
                score=0.5, label="unknown",
                backend="error", latency_ms=0.0,
            )

    def generate(self, prompt: str, max_tokens: int = 256) -> GenerateResult:
        """Generate text using the best available LLM backend.

        Tries: local LLM → cloud (via AEGIS inference) → template fallback
        """
        start = time.monotonic()

        # Try local LLM first
        if self._llm_engine:
            try:
                text = self._llm_engine.generate(prompt, max_tokens)
                if text:
                    latency = (time.monotonic() - start) * 1000
                    return GenerateResult(
                        text=text, backend="local_llm",
                        tokens=len(text.split()),
                        latency_ms=round(latency, 2),
                    )
            except Exception as e:
                logger.warning(f"Local LLM failed: {e}")

        # Try cloud via AEGIS inference module
        try:
            from core.aegis.inference import infer
            text = infer(prompt, max_tokens=max_tokens)
            if text:
                latency = (time.monotonic() - start) * 1000
                return GenerateResult(
                    text=text, backend="cloud",
                    tokens=len(text.split()),
                    latency_ms=round(latency, 2),
                )
        except (ImportError, Exception) as e:
            logger.debug(f"Cloud inference unavailable: {e}")

        # Template fallback
        latency = (time.monotonic() - start) * 1000
        return GenerateResult(
            text="[inference unavailable]", backend="template",
            tokens=0, latency_ms=round(latency, 2),
        )

    def embed(self, text: str) -> Optional[List[float]]:
        """Generate text embedding for RAG.

        Uses local LLM embedding if available, otherwise returns None
        (caller should fall back to Gemini API).
        """
        if self._llm_engine and hasattr(self._llm_engine, 'embed'):
            try:
                return self._llm_engine.embed(text)
            except Exception as e:
                logger.warning(f"Local embedding failed: {e}")
        return None

    def device_info(self) -> Dict[str, Any]:
        """Return hardware and engine information."""
        return {
            "hardware": self.hw.to_dict(),
            "tier": self.tier,
            "classify_engine": self._classify_engine.name if self._classify_engine else "none",
            "llm_engine": type(self._llm_engine).__name__ if self._llm_engine else "none",
            "llm_available": self._llm_engine is not None,
        }

    def model_info(self) -> Dict[str, Any]:
        """Return loaded model information."""
        info = {"classify_model": None, "llm_model": None}
        if self._classify_engine and hasattr(self._classify_engine, 'model_info'):
            info["classify_model"] = self._classify_engine.model_info()
        if self._llm_engine and hasattr(self._llm_engine, 'model_info'):
            info["llm_model"] = self._llm_engine.model_info()
        return info


# --- Built-in engines (no external dependencies) ---

class _RuleBasedClassifier:
    """Sentinel-tier: simple threshold classifier, no ML."""
    name = "rule-based"

    def score(self, features: np.ndarray) -> List[float]:
        """Score based on simple heuristics (high pps, high syn_ratio, etc.)."""
        scores = []
        for row in features:
            # Basic threat indicators from feature positions
            # pps=0, bps=1, unique_ports=2, syn_ratio=4, iat_entropy=9
            s = 0.0
            if len(row) > 0 and row[0] > 10000:  # High packet rate
                s += 0.3
            if len(row) > 4 and row[4] > 0.8:    # High SYN ratio
                s += 0.3
            if len(row) > 2 and row[2] > 100:     # Many unique ports
                s += 0.2
            if len(row) > 9 and row[9] > 3.0:     # High IAT entropy
                s += 0.1
            scores.append(min(s, 1.0))
        return scores

    def model_info(self) -> dict:
        return {"type": "rule-based", "features": "threshold", "version": "1.0"}


class _CPUClassifier:
    """CPU-based sklearn classifier using existing Isolation Forest."""
    name = "cpu-sklearn"

    def __init__(self):
        self._model = None
        self._model_loaded = False
        self._load_model()

    def _load_model(self):
        """Try to load the existing Isolation Forest model."""
        model_dir = Path(os.environ.get("MODEL_DIR", "/app/models"))
        model_path = model_dir / "isolation_forest.pkl"

        if not model_path.exists():
            # Try alternate locations
            for alt in [
                Path("/opt/hookprobe/models/isolation_forest.pkl"),
                Path.home() / "hookprobe" / "models" / "isolation_forest.pkl",
            ]:
                if alt.exists():
                    model_path = alt
                    break

        if model_path.exists():
            try:
                # Use the HMAC-verified loading from anomaly_detector
                import hmac
                import hashlib
                import pickle

                key_str = os.environ.get("HOOKPROBE_MODEL_KEY")
                if not key_str:
                    logger.error("HOOKPROBE_MODEL_KEY env var not set — refusing to load model")
                    return
                key = key_str.encode()
                sig_path = model_path.with_suffix(model_path.suffix + ".sig")

                data = model_path.read_bytes()
                if sig_path.exists():
                    expected_sig = sig_path.read_bytes()
                    computed_sig = hmac.new(key, data, hashlib.sha256).digest()
                    if not hmac.compare_digest(computed_sig, expected_sig):
                        logger.error("Model signature mismatch — refusing to load")
                        return
                else:
                    # SA-05 fix: refuse to load unsigned models (CWE-502)
                    logger.warning(f"No .sig file for model {model_path}, refusing to load unsigned model")
                    return

                self._model = pickle.loads(data)
                self._model_loaded = True
                logger.info(f"Loaded Isolation Forest from {model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")

    def score(self, features: np.ndarray) -> List[float]:
        """Score features using Isolation Forest."""
        if not self._model_loaded or self._model is None:
            return [0.5] * len(features)  # Uninformed prior

        try:
            if hasattr(self._model, 'score_samples'):
                # sklearn IsolationForest
                raw_scores = self._model.score_samples(features)
                # Convert sklearn scores (negative = anomalous) to 0-1 range
                scores = [1.0 / (1.0 + np.exp(s)) for s in raw_scores]
                return scores
            elif hasattr(self._model, 'score'):
                # Our custom IsolationForest
                return self._model.score(features)
            else:
                return [0.5] * len(features)
        except Exception as e:
            logger.error(f"Scoring failed: {e}")
            return [0.5] * len(features)

    def model_info(self) -> dict:
        return {
            "type": "isolation-forest",
            "backend": "cpu-sklearn",
            "loaded": self._model_loaded,
            "features": HYDRA_FEATURE_DIMS,
        }


# --- CLI entry point ---
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    hw = detect_hardware()
    bridge = InferenceBridge(tier="auto", hw_profile=hw)
    print(json.dumps(bridge.device_info(), indent=2))

    # Test classification with random features
    test_features = np.random.rand(HYDRA_FEATURE_DIMS).astype(np.float32)
    result = bridge.classify(test_features)
    print(f"\nClassification: score={result.score:.3f}, label={result.label}, "
          f"backend={result.backend}, latency={result.latency_ms}ms")
