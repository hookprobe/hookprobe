"""
HookProbe NPU Engine — NVIDIA Jetson via TensorRT

Supports: Jetson Orin Nano Super (67 TOPS GPU)
Model format: TensorRT engine (.engine) or ONNX
SDK: TensorRT (pre-installed on JetPack)
Device: nvidia-smi / /proc/device-tree/compatible contains nvidia,orin
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _require_sdk():
    try:
        import tensorrt as trt
        return trt
    except ImportError:
        raise RuntimeError(
            "TensorRT not installed. On Jetson, use JetPack SDK:\n"
            "  sudo apt install nvidia-jetpack\n"
            "  pip install tensorrt"
        )


class TensorRTEngine:
    """Anomaly detection on NVIDIA Jetson via TensorRT."""

    def __init__(self, model_path: str, **kwargs):
        trt = _require_sdk()
        import pycuda.autoinit  # noqa: F401
        import pycuda.driver as cuda
        if not Path(model_path).exists():
            raise FileNotFoundError(f"TensorRT model not found: {model_path}")
        self._model_path = model_path
        trt_logger = trt.Logger(trt.Logger.WARNING)
        with open(model_path, "rb") as f, trt.Runtime(trt_logger) as runtime:
            self._engine = runtime.deserialize_cuda_engine(f.read())
        self._context = self._engine.create_execution_context()
        self._cuda = cuda
        logger.info(f"TensorRTEngine loaded: {Path(model_path).name}")

    def classify(self, features: list) -> dict:
        import numpy as np
        input_data = np.array(features, dtype=np.float32).reshape(1, -1)
        output_data = np.empty(1, dtype=np.float32)
        d_input = self._cuda.mem_alloc(input_data.nbytes)
        d_output = self._cuda.mem_alloc(output_data.nbytes)
        self._cuda.memcpy_htod(d_input, input_data)
        self._context.execute_v2([int(d_input), int(d_output)])
        self._cuda.memcpy_dtoh(output_data, d_output)
        score = max(0.0, min(1.0, float(output_data[0])))
        label = "benign" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        return {"score": score, "label": label}

    @classmethod
    def is_available(cls) -> bool:
        try:
            compat = Path("/proc/device-tree/compatible").read_text(errors="ignore")
            return "nvidia,orin" in compat
        except Exception:
            return False

    def device_info(self) -> dict:
        return {
            "accelerator": "NVIDIA Jetson", "backend": "TensorRT",
            "model_format": "TensorRT Engine", "model": Path(self._model_path).name, "tops": 67,
        }
