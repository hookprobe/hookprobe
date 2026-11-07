"""
NPU Bridge — Hardware Acceleration for CNO Inference

Wires the existing hw_detect.py + inference_bridge.py into the CNO
for accelerated anomaly detection and classification.

Uses NPU when available, falls back to CPU gracefully.

Acceleration targets:
    - Anomaly scoring (24-dim feature vectors → anomaly score)
    - Intent classification (32-dim NAPSE features → 8 intent classes)
    - Behavioral token embedding (for Flash-RAG similarity search)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Try importing the existing brain modules
_HW_AVAILABLE = False
_hw_profile = None
_inference_bridge = None

try:
    import sys
    # Add hookprobe core to path if not already there
    hookprobe_core = '/home/ubuntu/hookprobe'
    if hookprobe_core not in sys.path:
        sys.path.insert(0, hookprobe_core)

    from core.brain.hw_detect import detect_hardware, HardwareProfile
    _hw_profile = detect_hardware()
    _HW_AVAILABLE = True
    logger.info("NPU Bridge: detected %s (%s TOPS)",
                _hw_profile.accelerator.value if _hw_profile else 'none',
                _hw_profile.tops if _hw_profile else 0)
except ImportError:
    logger.info("NPU Bridge: hw_detect not available, using CPU fallback")
except Exception as e:
    logger.warning("NPU Bridge: hardware detection failed: %s", e)


class NPUBridge:
    """Bridges NPU hardware acceleration into the CNO.

    Provides a unified interface for accelerated ML inference,
    falling back to CPU when no NPU is detected.
    """

    def __init__(self):
        self._hw_profile = _hw_profile
        self._has_npu = _HW_AVAILABLE and _hw_profile is not None
        self._inference_engine = None

        # Stats
        self._stats = {
            'classify_calls': 0,
            'classify_npu': 0,
            'classify_cpu': 0,
            'avg_latency_us': 0.0,
            'errors': 0,
        }

        if self._has_npu:
            self._init_engine()

        logger.info("NPUBridge initialized (npu=%s, type=%s)",
                     self._has_npu,
                     _hw_profile.accelerator.value if _hw_profile else 'cpu')

    def _init_engine(self) -> None:
        """Initialize the inference engine based on detected hardware."""
        try:
            from core.brain.inference_bridge import InferenceBridge
            tier = os.environ.get('HOOKPROBE_TIER', 'fortress')
            self._inference_engine = InferenceBridge(
                tier=tier, hw_profile=self._hw_profile
            )
            logger.info("NPU inference engine initialized (tier=%s)", tier)
        except Exception as e:
            logger.warning("Failed to initialize inference engine: %s", e)
            self._inference_engine = None

    # ------------------------------------------------------------------
    # Accelerated Classification
    # ------------------------------------------------------------------

    def classify_anomaly(self, features: List[float]) -> Tuple[float, str]:
        """Classify a feature vector as anomalous.

        Returns (anomaly_score, method) where method is 'npu' or 'cpu'.
        """
        self._stats['classify_calls'] += 1
        start = time.monotonic()

        try:
            if self._inference_engine:
                result = self._inference_engine.classify(features)
                method = 'npu' if self._has_npu else 'cpu'
                self._stats[f'classify_{method}'] += 1
                score = result.get('score', 0.5) if isinstance(result, dict) else float(result)
            else:
                # CPU fallback: simple statistical anomaly score
                score = self._cpu_anomaly_score(features)
                method = 'cpu'
                self._stats['classify_cpu'] += 1

        except Exception as e:
            logger.debug("Classification error: %s", e)
            score = 0.5  # Neutral on error
            method = 'cpu'
            self._stats['errors'] += 1

        elapsed_us = int((time.monotonic() - start) * 1_000_000)
        n = self._stats['classify_calls']
        self._stats['avg_latency_us'] = (
            self._stats['avg_latency_us'] * (n - 1) + elapsed_us
        ) / n

        return score, method

    def _cpu_anomaly_score(self, features: List[float]) -> float:
        """Simple CPU-based anomaly score using feature magnitude.

        Not a real ML model — just a heuristic for when no NPU/model
        is available. Returns 0.0-1.0.
        """
        if not features:
            return 0.0

        # Magnitude-based: higher values in key features = more anomalous
        # Features 0-3: pps, bps, unique_dst_ports, unique_dst_ips
        # Features 4-5: syn_ratio, rst_ratio
        key_features = features[:6] if len(features) >= 6 else features

        # Normalize: assume most features are 0-1 already (from feature_extractor)
        magnitude = sum(abs(f) for f in key_features) / len(key_features)
        return min(magnitude, 1.0)

    # ------------------------------------------------------------------
    # Batch Classification
    # ------------------------------------------------------------------

    def classify_batch(self, feature_vectors: List[List[float]]) -> List[Tuple[float, str]]:
        """Classify a batch of feature vectors.

        NPU acceleration is most beneficial for batch operations.
        """
        return [self.classify_anomaly(fv) for fv in feature_vectors]

    # ------------------------------------------------------------------
    # Hardware Info
    # ------------------------------------------------------------------

    def get_hw_info(self) -> Dict[str, Any]:
        """Return detected hardware information."""
        if not self._hw_profile:
            return {
                'accelerator': 'cpu',
                'tops': 0,
                'framework': 'none',
                'available': False,
            }

        return {
            'accelerator': self._hw_profile.accelerator.value,
            'tops': self._hw_profile.tops,
            'memory_mb': getattr(self._hw_profile, 'memory_mb', 0),
            'framework': getattr(self._hw_profile, 'framework', 'unknown'),
            'available': True,
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'hardware': self.get_hw_info(),
        }
