"""
HookProbe NPU Engine — Google Coral + Qualcomm via LiteRT (TFLite)

Supports:
  - Google Coral Edge TPU (4 TOPS) — USB/M.2
  - Qualcomm QCS8550 (48 TOPS) / QCS6490 (12 TOPS)
  - BeagleY-AI TI AM67A (4 TOPS)
  - CPU fallback (any platform)

Model format: TFLite (.tflite), quantized INT8
SDK: pip install ai-edge-litert  (or pip install tflite-runtime)
Device: /dev/apex_0 (Coral), /dev/qcom-npu (Qualcomm)
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _require_sdk():
    try:
        from tflite_runtime.interpreter import Interpreter
        return Interpreter
    except ImportError:
        try:
            from ai_edge_litert import Interpreter
            return Interpreter
        except ImportError:
            raise RuntimeError(
                "LiteRT/TFLite not installed. Run one of:\n"
                "  pip install ai-edge-litert\n"
                "  pip install tflite-runtime\n"
                "  # Coral: pip install tflite-runtime[edgetpu]"
            )


class LiteRTEngine:
    """Anomaly detection via Google LiteRT (TFLite)."""

    def __init__(self, model_path: str, **kwargs):
        Interpreter = _require_sdk()
        if not Path(model_path).exists():
            raise FileNotFoundError(f"TFLite model not found: {model_path}")
        self._model_path = model_path
        delegate = kwargs.get("delegate")
        delegates = []
        if delegate == "edgetpu":
            from tflite_runtime.interpreter import load_delegate
            delegates = [load_delegate("libedgetpu.so.1")]
        self._interp = Interpreter(model_path=model_path, experimental_delegates=delegates or None)
        self._interp.allocate_tensors()
        self._input_details = self._interp.get_input_details()
        self._output_details = self._interp.get_output_details()
        logger.info(f"LiteRTEngine loaded: {Path(model_path).name}")

    def classify(self, features: list) -> dict:
        import numpy as np
        input_data = np.array(features, dtype=np.float32).reshape(
            self._input_details[0]["shape"]
        )
        self._interp.set_tensor(self._input_details[0]["index"], input_data)
        self._interp.invoke()
        output = self._interp.get_tensor(self._output_details[0]["index"])
        score = float(output.flatten()[0])
        score = max(0.0, min(1.0, score))
        label = "benign" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        return {"score": score, "label": label}

    @classmethod
    def is_available(cls) -> bool:
        try:
            _require_sdk()
            return True
        except RuntimeError:
            return False

    def device_info(self) -> dict:
        device = "CPU"
        if os.path.exists("/dev/apex_0"):
            device = "Google Coral TPU"
        elif os.path.exists("/sys/devices/platform/soc/soc:qcom,npu"):
            device = "Qualcomm NPU"
        return {
            "accelerator": device, "backend": "LiteRT",
            "model_format": "TFLite", "model": Path(self._model_path).name,
        }
