#!/usr/bin/env python3
"""End-to-end check of the HookProbe SBC design: requirements -> schematic -> board.

    python3 validate.py            # everything (the schematic rules check takes several minutes)
    python3 validate.py --quick    # skip regenerating and rules-checking the schematic

Writes VALIDATION.md next to this script and exits non-zero if any check fails.
Checks:
  1. Schematic: KiCad's netlist matches the intended connections; KiCad electrical rules check.
  2. Board against schematic: every schematic part is on the board exactly once, with the same footprint,
     and every pad carries the same net as its schematic pin. KiCad's own schematic-parity check too.
  3. Placement: parts on the board outline, the processor and both RAM chips inside the cooler square,
     every external port on the rear edge, corner holes, M.2 sockets on the underside, no overlaps.
  4. KiCad board check (DRC) under JLCPCB's limits (tools/board_rules.py): no errors allowed.
     Power tree (design/power_check.py): regulator voltages, pin limits, enable pins, power-up order, loads.
  5. Requirements: each item of the original feature list traced to parts and nets.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "schematic"))
sys.path.insert(0, os.path.join(HERE, "tools"))
import build  # noqa: E402
import build_pcb  # noqa: E402
import kicadgen as kg  # noqa: E402

BOARD = os.path.join(HERE, "schematic", "hookprobe-sbc.kicad_pcb")
CLI = build.KICAD_CLI
results = []          # (section, ok, text)


def check(section, ok, text):
    results.append((section, bool(ok), text))
    print(("  ok    " if ok else "  FAIL  ") + text)


# ------------------------------------------------------------ board reading --
def read_board():
    """{ref: {value, fp, side, x, y, rot, pads: {pad: net}}} plus the outline size, from the board file."""
    tree = kg.parse(open(BOARD, encoding="utf-8").read())
    fps = {}
    for fp in kg.find_all(tree, "footprint"):
        props = {str(p[1]): str(p[2]) for p in kg.find_all(fp, "property")}
        tf = kg.find(fp, "transform")            # this KiCad build stores the position as a transform
        if tf is not None:
            tr, rt = kg.find(tf, "translate"), kg.find(tf, "rotate")
            at = ["at", tr[1], tr[2]] + ([rt[1]] if rt else [])
        else:
            at = kg.find(fp, "at")
        pads = {}
        for pad in kg.find_all(fp, "pad"):
            net = kg.find(pad, "net")
            name = str(net[-1]) if net else ""
            num = str(pad[1])
            if num in pads and pads[num] != name and name:
                pads[num] = pads[num] or name
            else:
                pads.setdefault(num, name)
        ref = props.get("Reference", "?")
        fps[ref] = {"value": props.get("Value", ""), "fp": str(fp[1]), "side": str(kg.find(fp, "layer")[1]),
                    "x": float(at[1]), "y": float(at[2]), "rot": float(at[3]) if len(at) > 3 else 0.0,
                    "pads": pads}
    return fps


# ---------------------------------------------------------------- sections --
def schematic_section(quick):
    print("\n1. Schematic")
    if quick:
        check("Schematic", True, "skipped (--quick): run without it for the netlist cross-check and rules check")
        return
    build_pcb.collect()                 # builds and writes the schematic once, shared with the board steps
    ok = build.verify()
    check("Schematic", ok, "netlist cross-check and KiCad rules check (details above)")


def parity_section(parts, board):
    print("\n2. Board against schematic")
    missing = [r for r in parts if r not in board]
    check("Board vs schematic", not missing, "every schematic part is on the board (%d parts)%s"
          % (len(parts), "; missing: " + ", ".join(missing[:10]) if missing else ""))
    extra = [r for r in board if r not in parts and not r.startswith("H")]
    check("Board vs schematic", not extra, "no extra parts on the board besides mounting holes%s"
          % ("; extra: " + ", ".join(extra[:10]) if extra else ""))
    wrong_fp = [r for r in parts if r in board and board[r]["fp"] != parts[r]["fp"]]
    check("Board vs schematic", not wrong_fp, "every part has its schematic footprint%s"
          % ("; differs: " + ", ".join(wrong_fp[:10]) if wrong_fp else ""))
    bad = []
    pins = 0
    for ref, d in parts.items():
        if ref not in board:
            continue
        for pin, net in d["pins"].items():
            if not net or net.startswith("unconnected-"):
                continue
            pins += 1
            got = board[ref]["pads"].get(pin)
            if got != net:
                bad.append("%s.%s schematic %s board %s" % (ref, pin, net, got))
    check("Board vs schematic", not bad, "all %d schematic pin connections carried to the board pads%s"
          % (pins, "; e.g. " + "; ".join(bad[:5]) if bad else ""))
    floating = [(r, p) for r in parts if r in board for p, n in board[r]["pads"].items()
                if n and not n.startswith("unconnected-") and p in parts[r]["pins"]
                and (parts[r]["pins"].get(p) or "").startswith("unconnected-")]
    check("Board vs schematic", not floating, "no pad has a net that the schematic leaves unconnected")
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "drc.json")
        subprocess.run([CLI, "pcb", "drc", "--schematic-parity", "--format", "json", "--severity-all", "-o", out,
                        BOARD], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        rep = json.load(open(out))
    par = rep.get("schematic_parity", [])
    check("Board vs schematic", not par, "KiCad's own schematic-parity check: %d issue(s)%s"
          % (len(par), "; e.g. " + "; ".join(i.get("description", "") for i in par[:3]) if par else ""))
    return rep


def placement_section(parts, board, layout):
    print("\n3. Placement")
    w, h = build_pcb.BOARD_W, build_pcb.BOARD_H
    off = [r for r, v in layout.placed.items() if v[3][0] < -0.01 or v[3][1] < -0.01 or v[3][2] > w + 0.01
           or v[3][3] > h + 0.01]
    check("Placement", not off, "all %d footprints inside the %g x %g mm outline" % (len(layout.placed), w, h))
    cx, cy = build_pcb.COOLER_CENTRE
    half = build_pcb.COOLER_SIZE / 2
    cool = (cx - half, cy - half, cx + half, cy + half)
    for value in ("RK3588", "LPDDR4X 200-ball"):
        for ref in [r for r in parts if parts[r]["value"] == value]:
            b = layout.placed[ref][3]
            inside = cool[0] <= b[0] and cool[1] <= b[1] and b[2] <= cool[2] and b[3] <= cool[3]
            check("Placement", inside and not layout.placed[ref][4],
                  "%s (%s) on top, inside the 40 x 40 mm cooler square" % (ref, value))
    under_cooler = [r for r, v in layout.placed.items() if not v[4] and r in parts
                    and parts[r]["value"] not in ("RK3588", "LPDDR4X 200-ball")
                    and v[3][0] < cool[2] and cool[0] < v[3][2] and v[3][1] < cool[3] and cool[1] < v[3][3]]
    check("Placement", not under_cooler, "nothing else on top inside the cooler square%s"
          % ("; found: " + ", ".join(under_cooler[:8]) if under_cooler else ""))
    soc = layout.placed[next(r for r in parts if parts[r]["value"] == "RK3588")][3]

    def gap(ref, box):
        b = layout.placed[ref][3]
        cx, cy = (b[0] + b[2]) / 2, (b[1] + b[3]) / 2
        dx, dy = max(box[0] - cx, 0, cx - box[2]), max(box[1] - cy, 0, cy - box[3])
        return (dx * dx + dy * dy) ** 0.5
    # high-current, low-voltage regulators and the eMMC must sit close to the processor
    for value, limit in (("RK806-1", 30), ("RK860-2", 40), ("RK860-3", 40), ("eMMC 153-ball", 40)):
        for ref in [r for r in parts if parts[r]["value"] == value]:
            check("Placement", gap(ref, soc) <= limit, "%s (%s) %.0f mm from the processor (limit %d mm)"
                  % (ref, value, gap(ref, soc), limit))
    # each port's chips (PHY, PD controller, ESD, power switch) within reach of its connector
    for sheet, text, _ in build_pcb.EDGE:
        if sheet == "power_entry":
            continue
        conn = next(r for r in parts if parts[r]["sheet"] == sheet and text in parts[r]["fp"])
        far = ["%s %.0f mm" % (r, gap(r, layout.placed[conn][3])) for r in parts
               if parts[r]["sheet"] == sheet and re.match(r"U\d", r) and gap(r, layout.placed[conn][3]) > 30]
        check("Placement", not far, "%s: every chip of the port circuit within 30 mm of connector %s%s"
              % (sheet, conn, "; far: " + ", ".join(far) if far else ""))
    emmc = [r for r in parts if parts[r]["value"] == "eMMC 153-ball"]
    check("Placement", emmc and all(r in layout.placed for r in emmc), "eMMC %s placed" % ", ".join(emmc))
    for sheet, text, _ in build_pcb.EDGE:
        ref = next(r for r in parts if parts[r]["sheet"] == sheet and text in parts[r]["fp"])
        b = layout.placed[ref][3]
        check("Placement", b[1] <= 0.5 and not layout.placed[ref][4],
              "%s (%s) on the rear edge, top side" % (ref, parts[ref]["value"]))
    for value, *_ in build_pcb.M2:
        ref = next(r for r in parts if parts[r]["value"] == value)
        check("Placement", layout.placed[ref][4] and layout.placed[ref][3][3] >= h - 3,
              "%s %s on the underside at the front edge" % (ref, value))
    holes = [v for r, v in layout.placed.items() if r.startswith("H") and r not in parts]
    corners = [(4, 4), (w - 4, 4), (4, h - 4), (w - 4, h - 4)]
    for x, y in corners:
        hit = any(abs(v[0] - x) < 0.01 and abs(v[1] - y) < 0.01 for v in holes)
        check("Placement", hit, "M3 case-mounting hole at corner (%g, %g)" % (x, y))
    check("Placement", len(layout.clash) == 0, "no overlaps, on either side, including through-hole pins, "
          "holes, vents and M.2 pegs (%d found)" % len(layout.clash))


def drc_section(rep):
    print("\n4. KiCad board check")
    errs = [v for v in rep.get("violations", []) if v["severity"] == "error"]
    cross = [v for v in errs if len(set(re.findall(r" of ([A-Z]+\d+)", " ".join(
        i.get("description", "") for i in v.get("items", []))))) > 1 or v["type"] == "items_not_allowed"]
    check("Board check", not cross, "no errors between different parts or keep-outs (%d)" % len(cross))
    check("Board check", not errs, "no errors at all under JLCPCB's published limits (%d)%s"
          % (len(errs), "; e.g. " + errs[0]["description"][:90] if errs else ""))
    check("Board check", True, "%d connections unrouted: expected, nothing is routed yet"
          % len(rep.get("unconnected_items", [])))


def requirements_section(parts):
    print("\n5. Requirements (original feature list)")
    nets = {}
    for ref, d in parts.items():
        for pin, net in d["pins"].items():
            if net:
                nets.setdefault(net.rsplit("/", 1)[-1] if net.startswith("/") else net, set()).add(ref)

    def count(value_part):
        return sum(1 for d in parts.values() if value_part in d["value"])

    def joined(net, *needles):
        refs = nets.get(net, set())
        return all(any(n in parts[r]["value"] for r in refs) for n in needles)

    check("Requirements", count("RK3588") == 1, "CPU: RK3588")
    check("Requirements", count("LPDDR4X") == 2, "RAM: two LPDDR4X chips (64-bit)")
    check("Requirements", count("eMMC") == 1, "storage: eMMC")
    check("Requirements", count("RTL8125") == 2 and count("HR911130C") == 2
          and joined("PCIE_ETH1_TX_P", "RK3588") and joined("PCIE_ETH2_TX_P", "RK3588"),
          "2 x 2.5 GbE: two RTL8125BG on their own PCIe lanes, two jacks (jack rated 1 Gb, see notes)")
    check("Requirements", count("ESP32-H2") == 1 and joined("UART3_TX_THREAD", "RK3588", "ESP32-H2"),
          "Matter / Thread radio built in, on a processor serial port")
    check("Requirements", count("Wi-Fi (E-key)") == 1 and joined("PCIE_WIFI_RX_P", "RK3588", "Wi-Fi"),
          "Wi-Fi: M.2 E-key slot on PCIe (tri-band card)")
    check("Requirements", count("5G modem") == 1 and count("nano-SIM") == 1 and joined("UIM_DATA", "5G modem", "nano-SIM")
          and joined("USB3_MODEM_RX_P", "RK3588", "5G modem"), "5G: M.2 B-key slot on USB 3, nano-SIM wired")
    check("Requirements", count("NVMe") == 1 and joined("PCIE_NVME_RX_P", "RK3588", "NVMe"), "NVMe: M.2 M-key slot")
    check("Requirements", count("Accelerator") == 1 and joined("PCIE_ACCEL_RX_P", "RK3588", "Accelerator"),
          "NPU / FPGA: M.2 M-key accelerator slot (and the RK3588's built-in NPU)")
    check("Requirements", count("USB-C") == 2 and all(joined("USBC%d_SBU1" % i, "RK3588") for i in (1, 2))
          and all(joined("USBC%d_SSTX1_P" % i, "RK3588") for i in (1, 2)) and count("FUSB302") == 2,
          "2 x USB-C with USB 3, DisplayPort and power delivery")
    check("Requirements", count("USB-A") == 1 and joined("USBA1_DP", "FE1.1s") and joined("USBA2_DP", "FE1.1s"),
          "2 x USB-A (one stacked connector, USB 2.0)")
    check("Requirements", count("HYM8563") == 1 and count("RTC battery") == 1, "RTC with battery")
    check("Requirements", count("SLB 9670") == 1, "TPM 2.0")
    check("Requirements", count("Fan 5 V") == 1, "fan header for the CPU/RAM cooler")


def main():
    quick = "--quick" in sys.argv
    schematic_section(quick)
    # collect parts from the schematic generator and rebuild the board model (placement) in memory
    cap = {}
    orig = build_pcb.pcbgen.Board.write

    def keep(self, path):
        cap["board"] = self
        return orig(self, path)
    build_pcb.pcbgen.Board.write = keep
    import contextlib
    import io
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        build_pcb.main()
    layout = cap["board"]
    m = re.search(r"clashes: (\d+)", log.getvalue())
    layout.clash = [] if m and m.group(1) == "0" else ["see build_pcb output"]
    parts = build_pcb.collect()
    board = read_board()
    rep = parity_section(parts, board)
    placement_section(parts, board, layout)
    drc_section(rep)
    print("\n   Power tree (design/power_check.py)")
    sys.path.insert(0, os.path.join(HERE, "design"))
    import power_check
    for ok, text in power_check.run(build.project):
        results.append(("Power tree", ok, text))
    requirements_section(parts)

    fails = [r for r in results if not r[1]]
    lines = ["# HookProbe SBC rev A: end-to-end validation", "",
             "Generated by `validate.py`. %d checks, %d failed." % (len(results), len(fails)), ""]
    section = None
    for sec, ok, text in results:
        if sec != section:
            lines += ["", "## " + sec, ""]
            section = sec
        lines.append("- %s %s" % ("PASS" if ok else "**FAIL**", text))
    lines += ["", "## Not covered by these checks", "",
              "- Signal integrity, power integrity and thermal performance (need simulation or a prototype).",
              "- Routing: nothing is routed, so these checks say nothing about track widths, impedance or length.",
              "- Footprints and pinouts from LCSC's library are only as good as that library; the processor's",
              "  ball map was cross-checked against the Radxa ROCK 5B schematic (817 of 1088 balls confirmed).",
              "- Component values copied from the reference design are not re-derived from datasheets.", ""]
    with open(os.path.join(HERE, "VALIDATION.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print("\n%d checks, %d failed. Report: VALIDATION.md" % (len(results), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
