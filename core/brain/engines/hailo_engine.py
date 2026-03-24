"""
HookProbe NPU Engine — Hailo-8 / Hailo-8L via HailoRT SDK

Supports: Hailo-8 (26 TOPS), Hailo-8L (13 TOPS) — RPi AI HAT+
Model format: HEF (Hailo Executable Format)
SDK: pip install hailort && sudo apt install hailo-all
Device: /dev/hailo0
"""

import logging
import os
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


def _require_sdk():
    try:
        import hailo_platform as hp
        return hp
    except ImportError:
        raise RuntimeError(
            "Hailo SDK not installed. Run:\n"
            "  pip install hailort\n"
            "  sudo apt install hailo-all  # RPi AI HAT+"
        )


class HailoEngine:
    """Anomaly detection on Hailo-8/8L NPU."""

    def __init__(self, model_path: str, **kwargs):
        hp = _require_sdk()
        if not Path(model_path).exists():
            raise FileNotFoundError(f"HEF model not found: {model_path}")
        self._model_path = model_path
        self._device = hp.VDevice()
        self._hef = hp.HEF(model_path)
        self._network_group = self._device.configure(self._hef)[0]
        self._input_vstreams = self._network_group.input_vstreams()
        self._output_vstreams = self._network_group.output_vstreams()
        logger.info(f"HailoEngine loaded: {Path(model_path).name}")

    def classify(self, features: list) -> dict:
        import numpy as np
        input_data = np.array(features, dtype=np.float32).reshape(1, -1)
        with self._network_group.activate():
            results = self._network_group.infer(
                {self._input_vstreams[0].name: input_data}
            )
            score = float(results[self._output_vstreams[0].name].flatten()[0])
        score = max(0.0, min(1.0, score))
        label = "benign" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        return {"score": score, "label": label}

    @classmethod
    def is_available(cls) -> bool:
        if not os.path.exists("/dev/hailo0"):
            return False
        try:
            _require_sdk()
            return True
        except RuntimeError:
            return False

    def device_info(self) -> dict:
        return {
            "accelerator": "Hailo-8/8L", "backend": "HailoRT",
            "model_format": "HEF", "model": Path(self._model_path).name,
        }
