#!/usr/bin/env python3
"""
HookProbe Hardware Detection — NPU/GPU/CPU Discovery

Detects AI accelerators across 13 hardware types and recommends the optimal
product tier + inference backend. Used by ALL product tiers at startup.

Supported accelerators (priority order):
  High-End:  Apple M4 ANE (38T), Jetson Orin (67T), Qualcomm QCS8550 (48T)
  Mid:       Hailo-8 (26T), Hailo-8L (13T), Intel NPU (11T), QCS6490 (12T)
  Entry:     RK3588 (6T), Coral TPU (4T), BeagleY-AI (4T), Khadas VIM4 (3.2T)
  Fallback:  CPU with SIMD (NEON/AVX2/AVX-512)

Mock support:
  Set HOOKPROBE_MOCK_NPU=hailo-8l (or any AcceleratorType value) for testing.

Usage:
    from core.brain.hw_detect import detect_hardware, recommend_tier
    hw = detect_hardware()
    print(f"Accelerator: {hw.accelerator.value} ({hw.tops} TOPS)")
    print(f"Recommended tier: {recommend_tier(hw)}")
"""

import logging
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class AcceleratorType(Enum):
    """All supported AI accelerator types."""
    # High-End (Business/Enterprise)
    APPLE_M4 = "apple-m4"
    JETSON_ORIN = "jetson-orin"
    QCS8550 = "qcs8550"
    # Mid Tier (Prosumer/SOHO)
    HAILO_8 = "hailo-8"
    HAILO_8L = "hailo-8l"
    INTEL_NPU = "intel-npu"
    QCS6490 = "qcs6490"
    # Entry Tier (Home/IoT)
    RK3588_NPU = "rk3588"
    CORAL_TPU = "coral-tpu"
    BEAGLE_AI = "beagle-ai"
    KHADAS_NPU = "khadas-vim4"
    # Fallback
    CPU_ONLY = "cpu"


# Accelerator specs: (tops, default_engine, default_quantization, max_model_mb)
_ACCELERATOR_SPECS = {
    AcceleratorType.APPLE_M4:   (38.0, "coreml+llama.cpp", "FP16", 0),  # max from RAM
    AcceleratorType.JETSON_ORIN:(67.0, "tensorrt",         "FP16", 0),
    AcceleratorType.QCS8550:    (48.0, "litert+qnn",       "INT8", 0),
    AcceleratorType.HAILO_8:    (26.0, "hailort",          "INT8", 512),
    AcceleratorType.HAILO_8L:   (13.0, "hailort",          "INT8", 512),
    AcceleratorType.INTEL_NPU:  (11.0, "openvino",         "INT4", 1024),
    AcceleratorType.QCS6490:    (12.0, "litert+qnn",       "INT8", 512),
    AcceleratorType.RK3588_NPU: (6.0,  "rknn",             "INT8", 512),
    AcceleratorType.CORAL_TPU:  (4.0,  "litert+edgetpu",   "INT8", 256),
    AcceleratorType.BEAGLE_AI:  (4.0,  "tidl",             "INT8", 256),
    AcceleratorType.KHADAS_NPU: (3.2,  "aml_npu",          "INT8", 256),
    AcceleratorType.CPU_ONLY:   (0.0,  "cpu",              "Q4_K_M", 0),
}


@dataclass
class HardwareProfile:
    """Complete hardware capability profile."""
    accelerator: AcceleratorType = AcceleratorType.CPU_ONLY
    tops: float = 0.0
    inference_engine: str = "cpu"
    quantization: str = "Q4_K_M"
    ram_mb: int = 0
    cpu_cores: int = 1
    cpu_arch: str = "unknown"
    simd_width: int = 0        # 128=NEON, 256=AVX2, 512=AVX-512
    max_model_mb: int = 0
    is_mock: bool = False

    @property
    def tier_recommendation(self) -> str:
        return recommend_tier(self)

    @property
    def can_run_llm(self) -> bool:
        return self.ram_mb >= 1024

    @property
    def llm_recommendation(self) -> str:
        if self.ram_mb < 1024:
            return "none"
        elif self.ram_mb < 2048:
            return "smollm-135m-q4"
        elif self.ram_mb < 4096:
            return "tinyllama-1.1b-q4"
        elif self.ram_mb < 16384:
            return "phi-3-mini-q4"
        else:
            return "llama-3.1-70b-q4"

    def to_dict(self) -> dict:
        return {
            "accelerator": self.accelerator.value,
            "tops": self.tops,
            "inference_engine": self.inference_engine,
            "quantization": self.quantization,
            "ram_mb": self.ram_mb,
            "cpu_cores": self.cpu_cores,
            "cpu_arch": self.cpu_arch,
            "simd_width": self.simd_width,
            "max_model_mb": self.max_model_mb,
            "tier_recommendation": self.tier_recommendation,
            "can_run_llm": self.can_run_llm,
            "llm_recommendation": self.llm_recommendation,
            "is_mock": self.is_mock,
        }


def _read_file(path: str, default: str = "") -> str:
    """Safely read a file, return default on any error."""
    try:
        return Path(path).read_text(errors="ignore").strip()
    except Exception:
        return default


def _get_ram_mb() -> int:
    """Get total system RAM in MB."""
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
        return int(page_size * page_count / (1024 * 1024))
    except Exception:
        return 0


def _get_cpu_info() -> tuple:
    """Returns (arch, cores, simd_width)."""
    arch = os.uname().machine  # aarch64, x86_64, etc.
    try:
        cores = os.cpu_count() or 1
    except Exception:
        cores = 1

    simd_width = 0
    if arch == "aarch64":
        simd_width = 128  # NEON is standard on ARMv8
        # Check for SVE (Scalable Vector Extension)
        cpuinfo = _read_file("/proc/cpuinfo")
        if "sve" in cpuinfo.lower():
            simd_width = 256
    elif arch == "x86_64":
        cpuinfo = _read_file("/proc/cpuinfo")
        if "avx512" in cpuinfo.lower():
            simd_width = 512
        elif "avx2" in cpuinfo.lower():
            simd_width = 256
        elif "sse" in cpuinfo.lower():
            simd_width = 128

    return arch, cores, simd_width


def _detect_device_tree(compat: str) -> Optional[AcceleratorType]:
    """Detect SoC via /proc/device-tree/compatible."""
    compat_lower = compat.lower()
    if "nvidia,orin" in compat_lower or "nvidia,tegra" in compat_lower:
        return AcceleratorType.JETSON_ORIN
    if "rockchip,rk3588" in compat_lower:
        return AcceleratorType.RK3588_NPU
    if "ti,am67" in compat_lower or "ti,am62" in compat_lower:
        return AcceleratorType.BEAGLE_AI
    if "amlogic,a311d2" in compat_lower:
        return AcceleratorType.KHADAS_NPU
    return None


def detect_hardware() -> HardwareProfile:
    """Detect the best available AI accelerator.

    Priority: highest TOPS first. Returns a HardwareProfile with
    accelerator type, capabilities, and tier recommendation.

    Set HOOKPROBE_MOCK_NPU env var to simulate hardware for testing.
    """
    # --- Mock support for testing ---
    mock_npu = os.environ.get("HOOKPROBE_MOCK_NPU", "").strip()
    if mock_npu:
        try:
            accel = AcceleratorType(mock_npu)
        except ValueError:
            logger.warning(f"Unknown mock NPU type: {mock_npu}, falling back to CPU")
            accel = AcceleratorType.CPU_ONLY

        tops, engine, quant, max_model = _ACCELERATOR_SPECS.get(
            accel, (0.0, "cpu", "Q4_K_M", 0)
        )
        ram_mb = _get_ram_mb() or 4096
        arch, cores, simd = _get_cpu_info()
        if max_model == 0:
            max_model = int(ram_mb * 0.7)  # 70% of RAM for models

        logger.info(f"Mock NPU: {accel.value} ({tops} TOPS)")
        return HardwareProfile(
            accelerator=accel, tops=tops, inference_engine=engine,
            quantization=quant, ram_mb=ram_mb, cpu_cores=cores,
            cpu_arch=arch, simd_width=simd, max_model_mb=max_model,
            is_mock=True,
        )

    # --- Real hardware detection ---
    ram_mb = _get_ram_mb()
    arch, cores, simd = _get_cpu_info()

    # Apple Neural Engine (macOS)
    if os.uname().sysname == "Darwin":
        tops, engine, quant, _ = _ACCELERATOR_SPECS[AcceleratorType.APPLE_M4]
        return HardwareProfile(
            accelerator=AcceleratorType.APPLE_M4, tops=tops,
            inference_engine=engine, quantization=quant,
            ram_mb=ram_mb, cpu_cores=cores, cpu_arch=arch,
            simd_width=simd, max_model_mb=int(ram_mb * 0.9),
        )

    # Jetson Orin (device-tree)
    compat = _read_file("/proc/device-tree/compatible")
    dt_accel = _detect_device_tree(compat)
    if dt_accel:
        tops, engine, quant, max_model = _ACCELERATOR_SPECS[dt_accel]
        if max_model == 0:
            max_model = int(ram_mb * 0.6)
        logger.info(f"Detected {dt_accel.value} via device-tree ({tops} TOPS)")
        return HardwareProfile(
            accelerator=dt_accel, tops=tops, inference_engine=engine,
            quantization=quant, ram_mb=ram_mb, cpu_cores=cores,
            cpu_arch=arch, simd_width=simd, max_model_mb=max_model,
        )

    # Hailo-8 / Hailo-8L (RPi AI HAT+)
    if Path("/dev/hailo0").exists():
        # Distinguish Hailo-8 (26T) from Hailo-8L (13T)
        is_hailo8 = False
        board_info = _read_file("/sys/class/hailo_chardev/hailo0/board_info")
        if board_info and "hailo8l" not in board_info.lower():
            is_hailo8 = "hailo8" in board_info.lower()

        accel = AcceleratorType.HAILO_8 if is_hailo8 else AcceleratorType.HAILO_8L
        tops, engine, quant, max_model = _ACCELERATOR_SPECS[accel]
        logger.info(f"Detected {accel.value} via /dev/hailo0 ({tops} TOPS)")
        return HardwareProfile(
            accelerator=accel, tops=tops, inference_engine=engine,
            quantization=quant, ram_mb=ram_mb, cpu_cores=cores,
            cpu_arch=arch, simd_width=simd, max_model_mb=max_model,
        )

    # Intel NPU / AI Boost (Meteor Lake+) — must have actual device entries
    accel_dir = Path("/sys/class/accel")
    has_intel_npu = False
    if accel_dir.exists() and arch == "x86_64":
        # Check for actual accelerator device entries (not just empty class dir)
        accel_devices = list(accel_dir.iterdir())
        if accel_devices:
            has_intel_npu = True
    if not has_intel_npu:
        # Also check /dev/accel* device nodes
        has_intel_npu = bool(list(Path("/dev").glob("accel*"))) and arch == "x86_64"

    if has_intel_npu:
        tops, engine, quant, max_model = _ACCELERATOR_SPECS[AcceleratorType.INTEL_NPU]
        logger.info(f"Detected Intel NPU via /sys/class/accel ({tops} TOPS)")
        return HardwareProfile(
            accelerator=AcceleratorType.INTEL_NPU, tops=tops,
            inference_engine=engine, quantization=quant,
            ram_mb=ram_mb, cpu_cores=cores, cpu_arch=arch,
            simd_width=simd, max_model_mb=max_model,
        )

    # Qualcomm QCS8550/QCS6490 (Dragonwing)
    for qcom_path in ["/sys/devices/platform/soc/soc:qcom,npu",
                       "/sys/bus/platform/drivers/qcom-nsp"]:
        if Path(qcom_path).exists():
            # QCS8550 has npu, QCS6490 has nsp
            accel = AcceleratorType.QCS8550 if "npu" in qcom_path else AcceleratorType.QCS6490
            tops, engine, quant, max_model = _ACCELERATOR_SPECS[accel]
            if max_model == 0:
                max_model = int(ram_mb * 0.6)
            logger.info(f"Detected {accel.value} via {qcom_path}")
            return HardwareProfile(
                accelerator=accel, tops=tops, inference_engine=engine,
                quantization=quant, ram_mb=ram_mb, cpu_cores=cores,
                cpu_arch=arch, simd_width=simd, max_model_mb=max_model,
            )

    # Rockchip RK3588 NPU
    if Path("/dev/rknpu").exists() or Path("/dev/rknpu_service").exists():
        tops, engine, quant, max_model = _ACCELERATOR_SPECS[AcceleratorType.RK3588_NPU]
        logger.info(f"Detected RK3588 NPU via /dev/rknpu ({tops} TOPS)")
        return HardwareProfile(
            accelerator=AcceleratorType.RK3588_NPU, tops=tops,
            inference_engine=engine, quantization=quant,
            ram_mb=ram_mb, cpu_cores=cores, cpu_arch=arch,
            simd_width=simd, max_model_mb=max_model,
        )

    # Google Coral Edge TPU
    if Path("/dev/apex_0").exists():
        tops, engine, quant, max_model = _ACCELERATOR_SPECS[AcceleratorType.CORAL_TPU]
        logger.info(f"Detected Coral TPU via /dev/apex_0 ({tops} TOPS)")
        return HardwareProfile(
            accelerator=AcceleratorType.CORAL_TPU, tops=tops,
            inference_engine=engine, quantization=quant,
            ram_mb=ram_mb, cpu_cores=cores, cpu_arch=arch,
            simd_width=simd, max_model_mb=max_model,
        )

    # CPU-only fallback
    cpu_tops = 2.0 if arch == "x86_64" else 0.5
    max_model = int(ram_mb * 0.2)  # Conservative: 20% of RAM for models
    logger.info(f"No NPU detected, using CPU ({arch}, {cores} cores, SIMD={simd})")
    return HardwareProfile(
        accelerator=AcceleratorType.CPU_ONLY, tops=cpu_tops,
        inference_engine="cpu", quantization="Q4_K_M",
        ram_mb=ram_mb, cpu_cores=cores, cpu_arch=arch,
        simd_width=simd, max_model_mb=max_model,
    )


def recommend_tier(profile: HardwareProfile) -> str:
    """Recommend the optimal product tier based on hardware capabilities."""
    if profile.ram_mb < 512:
        return "sentinel"
    elif profile.ram_mb < 3072:
        return "guardian"
    elif profile.ram_mb < 12288:
        return "fortress"
    else:
        return "nexus"


# --- CLI entry point ---
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    hw = detect_hardware()
    print(json.dumps(hw.to_dict(), indent=2))
