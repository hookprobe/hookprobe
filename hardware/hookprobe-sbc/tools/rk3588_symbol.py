"""Build the project's RK3588 schematic symbol from the LCSC/EasyEDA pin data.

The downloaded symbol (vendor/lcsc_C5156490) lists all 1088 balls correctly
numbered and named but splits them into eight arbitrary blocks. This regroups
them into functional units and gives each pin an electrical type, so each
sheet shows one function and the rules check can see supplies and grounds.

The pin data is LCSC's, not Rockchip's: it still has to be checked against the
Rockchip datasheet ball map before layout.
"""
import os
import re

import kicadgen as kg
from kicadgen import Q

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "..", "vendor", "lcsc_C5156490")
NAME = "RK3588"
FOOTPRINT_FILE = "FCBGA-1088_L23.0-W23.0-P0.65-TL_RK3588.kicad_mod"
FOOTPRINT = "%s:%s" % (kg.LIB, FOOTPRINT_FILE[:-len(".kicad_mod")])

UNITS = ["PCIe PHYs", "USB and Type-C PHYs", "DDR channel 0", "DDR channel 1", "Display and camera",
         "GPIO bank 0", "GPIO bank 1", "GPIO bank 2", "GPIO bank 3", "GPIO bank 4",
         "Core supplies", "System", "Ground"]

_SUPPLY = re.compile(r"AVDD|DVDD|VDDA|VDDH|VDDQ|AVCC|VPH|VDD_|_VDD|VCCIO|PMUIO\d|PMU_\dV|EMMCIO|OSC_\dV|VDDOTP|OTP_VPP")


def classify(name):
    """Return (unit name, electrical type) for a ball name."""
    if re.match(r"(A?VSS_\d+|PLL_AVSS|DDR_CH\d_PLL_AVSS)$", name):
        return "Ground", "power_in"
    bank = re.search(r"GPIO(\d)_[A-D]\d", name)
    if bank:
        return "GPIO bank " + bank.group(1), "bidirectional"
    kind = "power_in" if _SUPPLY.search(name) else "passive"
    if name.startswith("PCIE"):
        return "PCIe PHYs", kind
    if name.startswith(("TYPEC", "USB")):
        return "USB and Type-C PHYs", kind
    if name.startswith("DDR_CH0"):
        return "DDR channel 0", kind
    if name.startswith("DDR_CH1"):
        return "DDR channel 1", kind
    if name.startswith(("HDMI", "MIPI")):
        return "Display and camera", kind
    if re.match(r"VDD_(CPU|GPU|NPU|LOGIC|VDENC)", name):
        return "Core supplies", "power_in"
    return "System", kind


def _natural(name):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", name)]


def _effects(hide=False):
    eff = ["effects", ["font", ["size", "1.27", "1.27"]]]
    if hide:
        eff.append(["hide", "yes"])
    return eff


def build():
    """Return (symbol node, {unit name: [pin dicts]})."""
    with open(os.path.join(VENDOR, "rk3588.kicad_sym"), encoding="utf-8") as fh:
        vendor = kg.find_all(kg.parse(fh.read()), "symbol")[0]
    pins = kg.symbol_pins(vendor)
    if len(pins) != 1088 or len(set(p["number"] for p in pins)) != 1088:
        raise SystemExit("vendor RK3588 symbol does not have 1088 unique balls")
    groups = {u: [] for u in UNITS}
    for p in pins:
        unit, kind = classify(p["name"])
        groups[unit].append({"number": p["number"], "name": p["name"], "type": kind})

    def prop(name, value, y, hide):
        return ["property", Q(name), Q(value), ["at", "5.08", str(y), "0"], _effects(hide)]

    sym = ["symbol", Q(NAME), ["pin_names", ["offset", "1.016"]],
           ["exclude_from_sim", "no"], ["in_bom", "yes"], ["on_board", "yes"],
           prop("Reference", "U", 5.08, False), prop("Value", NAME, 7.62, False),
           prop("Footprint", FOOTPRINT, 0, True), prop("Datasheet", "", 0, True),
           prop("Description", "Rockchip RK3588, FCBGA-1088 23x23 mm 0.65 mm pitch (LCSC C5156490)", 0, True)]
    for index, unit in enumerate(UNITS, start=1):
        members = sorted(groups[unit], key=lambda p: _natural(p["name"]))
        sub = ["symbol", Q("%s_%d_1" % (NAME, index)), ["unit_name", Q(": " + unit)]]   # KiCad prints this right after the reference
        if unit == "Ground":
            # all ground balls stacked on one point: one visible supply pin, the rest hidden
            sub.append(["rectangle", ["start", "5.08", "2.54"], ["end", "25.4", "-2.54"],
                        ["stroke", ["width", "0.254"], ["type", "default"]], ["fill", ["type", "background"]]])
            for i, p in enumerate(members):
                pin = ["pin", "power_in" if i == 0 else "passive", "line", ["at", "0", "0", "0"],
                       ["length", "5.08"]]
                if i:
                    pin.append(["hide", "yes"])
                pin += [["name", Q("VSS"), _effects()], ["number", Q(p["number"]), _effects()]]
                sub.append(pin)
                p["name"] = "VSS"
        else:
            width = 6 + 1.0 * max(len(p["name"]) for p in members)
            sub.append(["rectangle", ["start", "5.08", "2.54"],
                        ["end", kg._fmt(5.08 + width), kg._fmt(-2.54 * len(members))],
                        ["stroke", ["width", "0.254"], ["type", "default"]], ["fill", ["type", "background"]]])
            for i, p in enumerate(members):
                shown = p["name"]
                sub.append(["pin", p["type"], "line", ["at", "0", kg._fmt(-2.54 * i), "0"], ["length", "5.08"],
                            ["name", Q(shown), _effects()], ["number", Q(p["number"]), _effects()]])
        sym.append(sub)
    sym.append(["embedded_fonts", "no"])
    return sym, groups


def build_named():
    """Like build(), but keeps each ground ball's own name (for cross-checks)."""
    with open(os.path.join(VENDOR, "rk3588.kicad_sym"), encoding="utf-8") as fh:
        vendor = kg.find_all(kg.parse(fh.read()), "symbol")[0]
    groups = {u: [] for u in UNITS}
    for p in kg.symbol_pins(vendor):
        groups[classify(p["name"])[0]].append({"number": p["number"], "name": p["name"]})
    return None, groups


def register(project):
    """Add the RK3588 symbol and footprint to the project libraries."""
    sym, groups = build()
    project.add_symbol(sym)
    project.add_footprint(os.path.join(VENDOR, "rk3588.pretty", FOOTPRINT_FILE))
    return groups


if __name__ == "__main__":
    _, groups = build()
    for unit in UNITS:
        print("%-22s %4d pins" % (unit, len(groups[unit])))
    print("%-22s %4d pins" % ("total", sum(len(v) for v in groups.values())))
