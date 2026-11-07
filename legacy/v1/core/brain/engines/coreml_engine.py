"""
HookProbe NPU Engine — Apple M4 via CoreML

Supports: Apple M4/M4 Pro Neural Engine (38 TOPS, 16-core ANE)
Model format: CoreML (.mlpackage or .mlmodel)
SDK: pip install coremltools (macOS only)
Platform: macOS / Apple Silicon only
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _require_sdk():
    try:
        import coremltools as ct
        return ct
    except ImportError:
        raise RuntimeError(
            "CoreML Tools not installed. Run:\n"
            "  pip install coremltools\n"
            "  # macOS only — requires Apple Silicon"
        )


class CoreMLEngine:
    """Anomaly detection on Apple M4 Neural Engine."""

    def __init__(self, model_path: str, **kwargs):
        ct = _require_sdk()
        if not Path(model_path).exists():
            raise FileNotFoundError(f"CoreML model not found: {model_path}")
        self._model_path = model_path
        self._model = ct.models.MLModel(model_path)
        compute = kwargs.get("compute", "ALL")  # CPU_AND_NE, CPU_AND_GPU, ALL
        logger.info(f"CoreMLEngine loaded: {Path(model_path).name} compute={compute}")

    def classify(self, features: list) -> dict:
        import numpy as np
        input_data = np.array(features, dtype=np.float32).reshape(1, -1)
        prediction = self._model.predict({"input": input_data})
        score = float(list(prediction.values())[0].flatten()[0])
        score = max(0.0, min(1.0, score))
        label = "benign" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        return {"score": score, "label": label}

    @classmethod
    def is_available(cls) -> bool:
        return os.uname().sysname == "Darwin" and "arm" in os.uname().machine

    def device_info(self) -> dict:
        return {
            "accelerator": "Apple Neural Engine", "backend": "CoreML",
            "model_format": "mlpackage", "model": Path(self._model_path).name, "tops": 38,
        }


def create_engine(hw_profile):
    """Factory function for inference_bridge.py integration."""
    model_dir = __import__('os').environ.get('HOOKPROBE_MODEL_DIR', '/opt/hookprobe/models')
    model_path = f"{model_dir}/hookprobe-anomaly-{hw_profile.accelerator.value}.mlpackage"
    return CoreMLEngine(model_path)
