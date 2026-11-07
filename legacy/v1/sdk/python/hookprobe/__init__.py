"""
HookProbe Python SDK — AI-Native Edge Security Platform

Provides programmatic access to HookProbe nodes for:
- Hardware detection and NPU capabilities
- Inference bridge (classify, generate, embed)
- Node telemetry and QSecBit scoring
- Threat intelligence (Bloom filter IOC sharing)
- MSSP API client

Quick start:
    from hookprobe import HookProbeClient, detect_hardware

    # Check hardware
    hw = detect_hardware()
    print(f"NPU: {hw.accelerator} ({hw.tops} TOPS)")

    # Connect to MSSP dashboard
    client = HookProbeClient("https://mssp.hookprobe.com", api_key="...")
    nodes = client.list_nodes()

    # Classify network features
    from hookprobe.inference import InferenceBridge
    bridge = InferenceBridge(tier='guardian')
    result = bridge.classify(features)
"""

__version__ = "0.1.0"
__author__ = "HookProbe Team"
__license__ = "AGPL-3.0"

# Re-export core modules
try:
    from core.brain.hw_detect import detect_hardware, HardwareProfile, AcceleratorType
    from core.brain.inference_bridge import InferenceBridge
except ImportError:
    # SDK can work standalone without core modules
    detect_hardware = None
    HardwareProfile = None
    AcceleratorType = None
    InferenceBridge = None

from hookprobe.client import HookProbeClient

__all__ = [
    'HookProbeClient',
    'detect_hardware',
    'HardwareProfile',
    'AcceleratorType',
    'InferenceBridge',
]
