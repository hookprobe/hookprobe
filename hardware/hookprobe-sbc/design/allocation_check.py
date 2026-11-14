#!/usr/bin/env python3
"""HookProbe SBC rev A: high-speed interface allocation and power budget checks.

Run:  python3 design/allocation_check.py
Exits non-zero if any check fails. Standard library only.
"""
import sys

# --------------------------------------------------------------------------
# RK3588 high-speed PHY map
# Source: mainline Linux arch/arm64/boot/dts/rockchip/rk3588-base.dtsi and
# rk3588-extra.dtsi (controller -> PHY), and
# rk3588-friendlyelec-cm3588-nas.dts (a shipping board that splits the PCIe3
# PHY into 4 x 1 lane using pcie3x4, pcie3x2, pcie2x1l0 and pcie2x1l1).
# --------------------------------------------------------------------------
PHY_LANES = {
    "pcie30phy": 4,
    "combphy0": 1,
    "combphy1": 1,
    "combphy2": 1,
    "usbdp0": 1,
    "usbdp1": 1,
}

LEGAL_PHYS = {
    "pcie3x4": {"pcie30phy"},
    "pcie3x2": {"pcie30phy"},
    "pcie2x1l0": {"combphy1", "pcie30phy"},
    "pcie2x1l1": {"combphy2", "pcie30phy"},
    "pcie2x1l2": {"combphy0"},
    "usb_host0_xhci": {"usbdp0"},
    "usb_host1_xhci": {"usbdp1"},
    "usb_host2_xhci": {"combphy2"},
    "sata0": {"combphy0"},
    "sata1": {"combphy1"},
    "sata2": {"combphy2"},
}

# (board function, SoC controller, PHY, lanes)
ALLOCATION = [
    ("NVMe M.2 M-key", "pcie3x4", "pcie30phy", 1),
    ("NPU/FPGA M.2 M-key", "pcie3x2", "pcie30phy", 1),
    ("2.5GbE port 1 (RTL8125)", "pcie2x1l0", "pcie30phy", 1),
    ("2.5GbE port 2 (RTL8125)", "pcie2x1l1", "pcie30phy", 1),
    ("Wi-Fi M.2 E-key", "pcie2x1l2", "combphy0", 1),
    ("USB-C port 1 (USB3 + DP)", "usb_host0_xhci", "usbdp0", 1),
    ("USB-C port 2 (USB3 + DP)", "usb_host1_xhci", "usbdp1", 1),
    ("USB3 hub -> 5G M.2 B-key + 2x USB-A", "usb_host2_xhci", "combphy2", 1),
]

# --------------------------------------------------------------------------
# Power budget. Currents are ESTIMATES of peak draw, to be replaced with
# datasheet figures as each part is chosen. Rails match schematic/build.py.
# --------------------------------------------------------------------------
RAILS = {  # name: (volts, converter rating in amps) -- five MP8759 converters, 8 A each
    "VCC5V0_SYS": (5.05, 8.0),
    "VCC4V0_SYS": (4.04, 8.0),
    "+3V3": (3.36, 8.0),
    "VCC_3V3_M2": (3.36, 8.0),
    "VCC_MODEM": (3.36, 8.0),
}

# (load, rail, peak amps, optional?)  optional = only present if fitted/used
LOADS = [
    ("RK3588 + LPDDR4X + eMMC via power chip and core regulators (about 16 W)", "VCC4V0_SYS", 4.0, False),
    ("USB-A x2 (0.9 A each)", "VCC5V0_SYS", 1.8, True),
    ("USB-C port 2 sourcing 5 V / 2 A (SY6280 switch limit)", "VCC5V0_SYS", 2.0, True),
    ("USB hub, PD controllers, fan", "VCC5V0_SYS", 0.3, False),
    ("NVMe SSD", "VCC_3V3_M2", 3.0, False),
    ("NPU/FPGA M.2 card", "VCC_3V3_M2", 3.0, True),
    ("Wi-Fi M.2 card", "+3V3", 1.5, False),
    ("RTL8125 x2 with their core regulators", "+3V3", 1.3, False),
    ("TPM, RTC, Thread radio, misc logic", "+3V3", 0.5, False),
    ("5G modem (transmit burst)", "VCC_MODEM", 4.0, True),
]

REGULATOR_MARGIN = 0.80   # do not load a converter beyond 80 % of its rating
CONVERSION_EFFICIENCY = 0.90

SUPPLIES_W = {   # VIN must stay between 5.5 V and 26 V (MP8759 limit)
    "USB-C PD 20 V / 3 A": 60.0,
    "USB-C PD 20 V / 5 A": 100.0,
    "DC 12 V / 10 A": 120.0,
    "DC 19-20 V / 6 A": 114.0,
}

failures = []


def check(ok, message):
    print(("  ok    " if ok else "  FAIL  ") + message)
    if not ok:
        failures.append(message)


def check_interfaces():
    print("High-speed interface allocation")
    seen = {}
    used = {phy: 0 for phy in PHY_LANES}
    for function, ctrl, phy, lanes in ALLOCATION:
        check(ctrl in LEGAL_PHYS, "%s: controller %s exists" % (function, ctrl))
        check(ctrl not in seen, "%s: controller %s not already used" % (function, ctrl))
        seen[ctrl] = function
        check(phy in LEGAL_PHYS.get(ctrl, ()), "%s: %s can be routed to %s" % (function, ctrl, phy))
        used[phy] = used.get(phy, 0) + lanes
    for phy, lanes in sorted(used.items()):
        check(lanes <= PHY_LANES[phy], "%s: %d of %d lanes used" % (phy, lanes, PHY_LANES[phy]))
    free = [phy for phy, lanes in sorted(used.items()) if lanes == 0]
    print("  note  unused PHYs: %s" % (", ".join(free) or "none"))


def check_power():
    print("\nPower budget (estimated peak currents)")
    totals = {}
    for name, (volts, rating) in RAILS.items():
        base = sum(a for _, rail, a, opt in LOADS if rail == name and not opt)
        full = sum(a for _, rail, a, _ in LOADS if rail == name)
        totals[name] = (base * volts, full * volts)
        check(full <= rating * REGULATOR_MARGIN,
              "%s: %.1f A worst case vs %.1f A allowed (%.0f A regulator)"
              % (name, full, rating * REGULATOR_MARGIN, rating))
    base_w = sum(b for b, _ in totals.values()) / CONVERSION_EFFICIENCY
    full_w = sum(f for _, f in totals.values()) / CONVERSION_EFFICIENCY
    print("  note  input power, base fit (no optional loads): %.0f W" % base_w)
    print("  note  input power, everything peaking at once:   %.0f W" % full_w)
    for supply, watts in SUPPLIES_W.items():
        verdict = "covers worst case" if watts >= full_w else (
            "covers base fit only" if watts >= base_w else "NOT ENOUGH even for base fit")
        print("  note  %-22s %5.0f W  %s" % (supply, watts, verdict))
    check(any(w >= full_w for w in SUPPLIES_W.values()), "at least one supply option covers the worst case")


if __name__ == "__main__":
    check_interfaces()
    check_power()
    print("\n%d failure(s)" % len(failures))
    sys.exit(1 if failures else 0)
