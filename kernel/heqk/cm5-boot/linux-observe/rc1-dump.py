#!/usr/bin/env python3
# HEQK "Linux-as-oracle" — dump the BCM2712 external PCIe RC1 register state AFTER
# Linux (pcie-brcmstb) trains it, so HEQK's bare-metal rtl8111::rc1_train() can
# replicate the exact trained-state values instead of guessing. This is the same
# technique that cracked the RP1 GEM (observe the working Linux driver, mirror it).
#
# Writes /rc1dump.txt on the rootfs AND echoes to the serial console (so the
# values also appear in the FTDI capture during boot). Requires `iomem=relaxed`
# on the kernel cmdline for the /dev/mem read of the controller MMIO.
#
# Run automatically by rc1-observe.service after multi-user.target.

import mmap
import os
import struct
import subprocess

OUT = "/rc1dump.txt"
BASE = 0x10_0011_0000  # RC1 (pcie1) controller CPU-physical base
# The registers rc1_train() touches, plus link-status + config regs.
OFFS = [
    0x4008, 0x4064, 0x4068, 0x4304, 0x184c, 0x40a4, 0x40a8, 0x405c,
    0x416c, 0x40a0, 0x04dc, 0x043c, 0x0188, 0x04f8, 0x9210,
    0x1100, 0x1104, 0x1108,
]


def sh(cmd):
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=25
        ).stdout
    except Exception as e:  # noqa: BLE001
        return f"(cmd failed: {e})\n"


with open(OUT, "w") as f:
    def log(s):
        f.write(str(s) + "\n")
        f.flush()
        print(str(s), flush=True)  # -> serial console (FTDI) too

    log("===== HEQK RC1 OBSERVE =====")
    log("--- dmesg (pcie / brcm / r8169) ---")
    log(sh("dmesg | grep -iE 'pcie|brcm|rescal|r8169|8168|link up|link down|serdes'"))
    log("--- lspci ---")
    log(sh("lspci -nnvvv 2>/dev/null || lspci -nn 2>/dev/null "
           "|| for d in /sys/bus/pci/devices/*; do echo $d $(cat $d/vendor) $(cat $d/device); done"))
    log("--- net interfaces ---")
    log(sh("ip -br link 2>/dev/null || ls /sys/class/net"))
    log(f"--- RC1 registers @ {hex(BASE)} (via /dev/mem, needs iomem=relaxed) ---")
    try:
        fd = os.open("/dev/mem", os.O_RDONLY | os.O_SYNC)
        m = mmap.mmap(fd, 0x10000, mmap.MAP_SHARED, mmap.PROT_READ, offset=BASE)
        for o in OFFS:
            v = struct.unpack("<I", m[o:o + 4])[0]
            log(f"  0x{o:04x}: 0x{v:08x}")
        st = struct.unpack("<I", m[0x4068:0x406c])[0]
        log(f"  STATUS 0x4068=0x{st:08x}: PORT={bool(st & 0x80)} "
            f"DL_ACTIVE={bool(st & 0x20)} PHYLINKUP={bool(st & 0x10)}")
        m.close()
        os.close(fd)
    except Exception as e:  # noqa: BLE001
        log(f"  /dev/mem read FAILED: {e}")
    log("===== END RC1 OBSERVE =====")
