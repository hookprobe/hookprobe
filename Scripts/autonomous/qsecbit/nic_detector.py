"""
NIC Detection and XDP Capability Management

Author: Andrei Toma
License: MIT
Version: 5.0
"""

import subprocess
import re
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict


class XDPMode(Enum):
    """
    XDP attachment modes with different layers of operation

    Performance hierarchy: XDP-hw (Layer 0) > XDP-drv (Layer 1) > XDP-skb (Layer 1.5)
    """
    DISABLED = "disabled"
    SKB = "xdp-skb"      # Generic XDP (Layer 1.5 - after SKB allocation, works on all NICs, partial bypass)
    DRV = "xdp-drv"      # Native XDP (Layer 1 - in NIC driver, requires driver support, full kernel bypass)
    HW = "xdp-hw"        # Hardware offload (Layer 0 - in NIC hardware ASIC, requires programmable NICs, ultra-fast)


@dataclass
class NICCapability:
    """NIC XDP/eBPF capability profile"""
    vendor: str
    model: str
    driver: str
    xdp_skb: bool = True   # All NICs support generic XDP
    xdp_drv: bool = False  # Native driver mode
    af_xdp: bool = False   # AF_XDP zero-copy sockets
    hw_offload: bool = False  # Hardware offload
    max_throughput: str = "1Gbps"
    notes: str = ""


# ✅ NIC Capability Matrix for XDP/eBPF Support
NIC_CAPABILITY_MATRIX = {
    # Raspberry Pi NICs (SKB only)
    "bcmgenet": NICCapability(
        vendor="Broadcom",
        model="RPi 4/5 SoC NIC",
        driver="bcmgenet",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="1Gbps",
        notes="Raspberry Pi internal NIC. SKB mode only."
    ),
    "r8152": NICCapability(
        vendor="Realtek",
        model="RTL8152/RTL8153 USB",
        driver="r8152",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="1Gbps",
        notes="USB NIC. Cannot use DRV mode. Limited throughput."
    ),

    # Realtek PCIe NICs (SKB only)
    "r8169": NICCapability(
        vendor="Realtek",
        model="RTL8111/8168/8125",
        driver="r8169",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="2.5Gbps",
        notes="Consumer NIC. SKB mode only. Not suitable for high-speed XDP."
    ),

    # Intel Entry-Level NICs (1Gbps - Full eBPF Support)
    "igb": NICCapability(
        vendor="Intel",
        model="I211/I219",
        driver="igb",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=False,
        max_throughput="1Gbps",
        notes="Entry-level Intel with full XDP-DRV support."
    ),
    "igc": NICCapability(
        vendor="Intel",
        model="I225/I226",
        driver="igc",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=False,
        max_throughput="2.5Gbps",
        notes="Intel N100 typical NIC. Full XDP-DRV support."
    ),

    # Intel Server NICs (10Gbps+ - Full XDP Support)
    "ixgbe": NICCapability(
        vendor="Intel",
        model="82599/X520 10GbE",
        driver="ixgbe",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=True,
        hw_offload=False,
        max_throughput="10Gbps",
        notes="Older 10G. AF_XDP supported but no DRV mode."
    ),
    "i40e": NICCapability(
        vendor="Intel",
        model="X710/XL710",
        driver="i40e",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=True,
        max_throughput="40Gbps",
        notes="Full XDP support. First Intel NIC with DRV mode."
    ),
    "ice": NICCapability(
        vendor="Intel",
        model="E810",
        driver="ice",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=True,
        max_throughput="100Gbps",
        notes="Modern Intel NIC. Best XDP performance."
    ),

    # Mellanox/NVIDIA ConnectX (Best XDP Support)
    "mlx4_en": NICCapability(
        vendor="Mellanox",
        model="ConnectX-3",
        driver="mlx4_en",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=True,
        hw_offload=False,
        max_throughput="40Gbps",
        notes="Older Mellanox. AF_XDP only."
    ),
    "mlx5_core": NICCapability(
        vendor="Mellanox",
        model="ConnectX-4/5/6/7",
        driver="mlx5_core",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=True,
        max_throughput="200Gbps",
        notes="Gold standard for XDP. Programmable pipelines."
    ),
}


class NICDetector:
    """Detect NIC hardware and XDP capabilities"""

    @staticmethod
    def get_primary_interface() -> Optional[str]:
        """Get primary network interface (non-loopback, has IP)"""
        try:
            # Get default route interface
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(r'dev\s+(\S+)', result.stdout)
                if match:
                    return match.group(1)

            # Fallback: first non-loopback interface with IP
            result = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'lo' not in line:
                        match = re.search(r'^\d+:\s+(\S+)', line)
                        if match:
                            return match.group(1)
        except Exception as e:
            print(f"Warning: Failed to detect primary interface: {e}")

        return None

    @staticmethod
    def get_driver(interface: str) -> Optional[str]:
        """Get NIC driver name for interface"""
        try:
            driver_path = Path(f"/sys/class/net/{interface}/device/driver")
            if driver_path.exists():
                driver_link = driver_path.resolve()
                return driver_link.name
        except Exception as e:
            print(f"Warning: Failed to detect driver for {interface}: {e}")

        return None

    @staticmethod
    def get_nic_info(interface: str) -> Dict[str, str]:
        """Get detailed NIC information"""
        info = {
            'interface': interface,
            'driver': None,
            'vendor': 'Unknown',
            'model': 'Unknown'
        }

        # Get driver
        info['driver'] = NICDetector.get_driver(interface)

        # Try to get vendor/model from ethtool
        try:
            result = subprocess.run(
                ["ethtool", "-i", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("driver:"):
                        info['driver'] = line.split(":", 1)[1].strip()
                    elif line.startswith("bus-info:"):
                        info['model'] = line.split(":", 1)[1].strip()
        except Exception:
            pass

        return info

    @staticmethod
    def detect_capability(interface: str) -> NICCapability:
        """Detect XDP capability for interface"""
        nic_info = NICDetector.get_nic_info(interface)
        driver = nic_info.get('driver')

        if driver and driver in NIC_CAPABILITY_MATRIX:
            return NIC_CAPABILITY_MATRIX[driver]

        # Unknown NIC - assume SKB only
        return NICCapability(
            vendor="Unknown",
            model=nic_info.get('model', 'Unknown'),
            driver=driver or "unknown",
            xdp_skb=True,
            xdp_drv=False,
            af_xdp=False,
            hw_offload=False,
            max_throughput="Unknown",
            notes=f"Unknown NIC. Defaulting to SKB mode only."
        )

    @staticmethod
    def select_xdp_mode(capability: NICCapability, prefer_drv: bool = True) -> XDPMode:
        """Select best XDP mode for NIC capability"""
        if prefer_drv and capability.xdp_drv:
            return XDPMode.DRV
        elif capability.xdp_skb:
            return XDPMode.SKB
        else:
            return XDPMode.DISABLED
