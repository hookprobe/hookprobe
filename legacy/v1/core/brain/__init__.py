"""
HookProbe Brain — Hardware Detection & Unified Inference

Shared module for ALL product tiers (Sentinel → Guardian → Fortress → Nexus).
Provides hardware NPU detection, tier recommendation, and a unified inference
bridge that auto-selects the optimal backend per device.

Usage:
    from core.brain.hw_detect import detect_hardware
    from core.brain.inference_bridge import InferenceBridge

    hw = detect_hardware()
    bridge = InferenceBridge(tier='guardian', hw_profile=hw)
    result = bridge.classify(features)
"""

from core.brain.hw_detect import detect_hardware, HardwareProfile, AcceleratorType

__all__ = ['detect_hardware', 'HardwareProfile', 'AcceleratorType']
