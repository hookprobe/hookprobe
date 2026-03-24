"""
HookProbe NPU Engine — Intel NPU via OpenVINO

Supports: Intel Meteor Lake/Lunar Lake (11 TOPS AI Boost)
Model format: OpenVINO IR (.xml + .bin)
SDK: pip install openvino
Device: /sys/class/accel (Intel NPU driver)
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _require_sdk():
    try:
        from openvino.runtime import Core
        return Core
    except ImportError:
        raise RuntimeError(
            "OpenVINO not installed. Run:\n"
            "  pip install openvino\n"
            "  # For NPU support: pip install openvino[npu]"
        )


class OpenVINOEngine:
    """Anomaly detection on Intel NPU via OpenVINO."""

    def __init__(self, model_path: str, **kwargs):
        Core = _require_sdk()
        if not Path(model_path).exists():
            raise FileNotFoundError(f"OpenVINO IR not found: {model_path}")
        self._model_path = model_path
        device = kwargs.get("device", "NPU")
        core = Core()
        model = core.read_model(model_path)
        self._compiled = core.compile_model(model, device)
        self._infer_request = self._compiled.create_infer_request()
        logger.info(f"OpenVINOEngine loaded: {Path(model_path).name} on {device}")

    def classify(self, features: list) -> dict:
        import numpy as np
        input_data = np.array(features, dtype=np.float32).reshape(1, -1)
        self._infer_request.infer({0: input_data})
        score = float(self._infer_request.get_output_tensor(0).data.flatten()[0])
        score = max(0.0, min(1.0, score))
        label = "benign" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        return {"score": score, "label": label}

    @classmethod
    def is_available(cls) -> bool:
        if not os.path.exists("/sys/class/accel"):
            return False
        try:
            _require_sdk()
            return True
        except RuntimeError:
            return False

    def device_info(self) -> dict:
        return {
            "accelerator": "Intel NPU", "backend": "OpenVINO",
            "model_format": "IR", "model": Path(self._model_path).name,
        }


def create_engine(hw_profile):
    """Factory function for inference_bridge.py integration."""
    model_dir = __import__('os').environ.get('HOOKPROBE_MODEL_DIR', '/opt/hookprobe/models')
    model_path = f"{model_dir}/hookprobe-anomaly-{hw_profile.accelerator.value}.xml"
    return OpenVINOEngine(model_path)
