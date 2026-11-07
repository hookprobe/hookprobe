"""
HookProbe Inference Engines — Per-Vendor NPU/GPU/CPU Backends

Each engine implements:
  - score(features: np.ndarray) -> List[float]  (classification)
  - create_engine(hw_profile) -> engine          (factory function)

Available engines (loaded dynamically by inference_bridge.py):
  - cpu_engine:      sklearn Isolation Forest (always available)
  - llama_engine:    llama-cpp-python for local LLM (optional)
  - hailo_engine:    Hailo-8/8L via HailoRT SDK (Phase 1.5)
  - openvino_engine: Intel NPU via OpenVINO (Phase 1.5)
  - rknn_engine:     Rockchip RK3588 via RKNN (Phase 1.5)
  - tensorrt_engine: NVIDIA Jetson via TensorRT (Phase 1.5)
  - coreml_engine:   Apple M4 via CoreML (Phase 1.5)
  - litert_engine:   Google LiteRT for Coral/Qualcomm (Phase 1.5)
"""
