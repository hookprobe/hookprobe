"""
HookProbe NPU Engine — Rockchip RK3588 via RKNN Toolkit

Supports: RK3588 (6 TOPS) — Radxa ROCK 5B+, Orange Pi 5
Model format: RKNN (convert from ONNX/TFLite/PyTorch)
SDK: pip install rknn-toolkit2 (or rknn-toolkit-lite2 for edge)
Device: /dev/rknpu
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _require_sdk():
    try:
        from rknnlite.api import RKNNLite
        return RKNNLite
    except ImportError:
        raise RuntimeError(
            "RKNN SDK not installed. Run:\n"
            "  pip install rknn-toolkit-lite2\n"
            "  # Full toolkit: pip install rknn-toolkit2"
        )


class RKNNEngine:
    """Anomaly detection on Rockchip RK3588 NPU."""

    def __init__(self, model_path: str, **kwargs):
        RKNNLite = _require_sdk()
        if not Path(model_path).exists():
            raise FileNotFoundError(f"RKNN model not found: {model_path}")
        self._model_path = model_path
        self._rknn = RKNNLite()
        self._rknn.load_rknn(model_path)
        self._rknn.init_runtime(core_mask=kwargs.get("core_mask", 0b111))
        logger.info(f"RKNNEngine loaded: {Path(model_path).name}")

    def classify(self, features: list) -> dict:
        import numpy as np
        input_data = np.array(features, dtype=np.float32).reshape(1, -1)
        outputs = self._rknn.inference(inputs=[input_data])
        score = float(outputs[0].flatten()[0])
        score = max(0.0, min(1.0, score))
        label = "benign" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        return {"score": score, "label": label}

    @classmethod
    def is_available(cls) -> bool:
        return os.path.exists("/dev/rknpu") or os.path.exists("/dev/rknpu_service")

    def device_info(self) -> dict:
        return {
            "accelerator": "RK3588 NPU", "backend": "RKNN",
            "model_format": "RKNN", "model": Path(self._model_path).name, "tops": 6,
        }


def create_engine(hw_profile):
    """Factory function for inference_bridge.py integration."""
    model_dir = __import__('os').environ.get('HOOKPROBE_MODEL_DIR', '/opt/hookprobe/models')
    model_path = f"{model_dir}/hookprobe-anomaly-{hw_profile.accelerator.value}.rknn"
    return RKNNEngine(model_path)
