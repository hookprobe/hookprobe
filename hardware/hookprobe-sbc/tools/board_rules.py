#!/usr/bin/env python3
"""Write JLCPCB's manufacturing limits and this board's net classes into the KiCad project file.

    python3 tools/board_rules.py

Limits: jlcpcb.com/capabilities/pcb-capabilities (multilayer FR-4, 1 oz outer copper), read 2026-11.
Track widths for controlled impedance are STARTING VALUES from the closed-form microstrip formulas below,
for the outer layers of an 8-layer 1.6 mm board with 0.0994 mm 3313 prepreg (dielectric constant 4.1).
Replace them with the figures from JLCPCB's impedance calculator for the stack-up actually ordered.
"""
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PRO = os.path.join(os.path.dirname(HERE), "schematic", "hookprobe-sbc.kicad_pro")

# JLCPCB limits, mm
JLC = {
    "min_clearance": 0.09,                 # track / space 3.5 mil on multilayer boards
    "min_track_width": 0.09,
    "min_via_diameter": 0.25,              # 0.15 mm hole, 0.25 mm pad is the smallest via
    "min_through_hole_diameter": 0.15,
    "min_via_annular_width": 0.05,
    "min_hole_clearance": 0.2,             # via to track
    "min_hole_to_hole": 0.2,
    "min_copper_edge_clearance": 0.2,      # routed edge
    "solder_mask_to_copper_clearance": 0.0,
    "min_microvia_diameter": 0.25,
    "min_microvia_drill": 0.15,
    "min_text_height": 0.8,
    "min_text_thickness": 0.12,
    "min_silk_clearance": 0.0,
    "min_connection": 0.0,
    "min_resolved_spokes": 1,
}

H, ER, T = 0.0994, 4.1, 0.035              # outer prepreg height, dielectric constant, copper thickness


def z0(w):
    """Surface microstrip impedance (IPC-2141 closed form)."""
    return 87.0 / math.sqrt(ER + 1.41) * math.log(5.98 * H / (0.8 * w + T))


def zdiff(w, s):
    return 2 * z0(w) * (1 - 0.48 * math.exp(-0.96 * s / H))


def width_for(target):
    w = 0.09
    while z0(w) > target and w < 1.0:
        w += 0.005
    return round(w, 3)


def pair_for(target, gap):
    w = 0.09
    while zdiff(w, gap) > target and w < 1.0:
        w += 0.005
    return round(w, 3)


def classes():
    w50 = width_for(50)
    out = [
        # name, track, clearance, via pad, via hole, pair width, pair gap, net patterns
        ("Default", 0.127, 0.09, 0.4, 0.2, 0.127, 0.127, []),
        ("Input_power", 0.8, 0.2, 0.6, 0.3, 0.2, 0.2, ["*VIN", "*DC_JACK", "*DC_IN", "*USBC1_VBUS", "*IN?_SW"]),
        ("Power", 0.5, 0.15, 0.5, 0.25, 0.2, 0.2,
         ["*VCC5V0_SYS", "*VCC4V0_SYS", "+3V3", "*VCC_3V3_M2", "*VCC_MODEM", "*USBA_VBUS", "*USBC2_VBUS",
          "*PMIC_SW*", "*SW_VDD_*", "*VCC_3V3_S?", "*VCC_1V8_S?", "*VDD2_DDR_S3", "*VDDQ_DDR_S0", "*VDD_DDR_S0"]),
        ("Core_power", 0.4, 0.1, 0.4, 0.2, 0.2, 0.2, ["*VDD_CPU_*", "*VDD_GPU_S0", "*VDD_NPU_S0", "*VDD_LOG_S0",
                                                        "*VDD_VDENC_S0"]),
        ("PCIe_85R", 0.127, 0.15, 0.4, 0.2, pair_for(85, 0.11), 0.11,
         ["*PCIE_*_TX_?", "*PCIE_*_RX_?", "*PCIE_*_REFCLK_?", "*_TXC_?", "*_HSI?", "*_HSO?", "*CLK?_OUT*"]),
        ("USB_90R", 0.127, 0.15, 0.4, 0.2, pair_for(90, 0.12), 0.12,
         ["*USB2_*_D?", "*USB3_*", "*USBC?_SS*", "*USBC?_TX?C_?", "*CONN_D?", "*USBA?_D?"]),
        ("Ethernet_100R", 0.127, 0.15, 0.4, 0.2, pair_for(100, 0.15), 0.15, ["*ETH?_MDI?_?"]),
        ("Memory", 0.09, 0.09, 0.4, 0.2, 0.09, 0.09, ["*DDR_CH?_*", "*DDR?_*", "*EMMC_*"]),
        ("Single_50R", w50, 0.12, 0.4, 0.2, w50, 0.15, ["*XIN24M", "*XOUT24M", "*SUSCLK_32K", "*SPI1_*"]),
    ]
    return out


def main():
    with open(PRO, encoding="utf-8") as fh:
        pro = json.load(fh)
    ds = pro.setdefault("board", {}).setdefault("design_settings", {})
    ds.setdefault("rules", {}).update(JLC)
    ds.setdefault("defaults", {})
    ns = pro.setdefault("net_settings", {})
    template = dict(ns.get("classes", [{}])[0])
    out, patterns = [], []
    for name, track, clearance, via, drill, pw, gap, pats in classes():
        c = dict(template)
        c.update({"name": name, "track_width": track, "clearance": clearance, "via_diameter": via, "via_drill": drill,
                  "diff_pair_width": pw, "diff_pair_gap": gap, "diff_pair_via_gap": 0.25})
        if name != "Default":
            c["priority"] = len(out)
        out.append(c)
        patterns += [{"netclass": name, "pattern": p} for p in pats]
    ns["classes"], ns["netclass_patterns"] = out, patterns
    with open(PRO, "w", encoding="utf-8") as fh:
        json.dump(pro, fh, indent=2)
        fh.write("\n")
    print("JLCPCB limits and %d net classes written to %s" % (len(out), os.path.basename(PRO)))
    for name, track, clearance, via, drill, pw, gap, pats in classes():
        extra = ""
        if "R" in name.split("_")[-1]:
            extra = "  (computed %.0f ohm)" % (zdiff(pw, gap) if name != "Single_50R" else z0(track))
        print("  %-14s track %.3f  clearance %.2f  via %.2f/%.2f  pair %.3f / %.2f%s"
              % (name, track, clearance, via, drill, pw, gap, extra))


if __name__ == "__main__":
    main()
