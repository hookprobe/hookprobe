"""Cross-check the memory wiring rule against the Radxa Rock 5B schematic (sheet 4).

For every signal ball of the LPDDR4X chip (ball names from the LCSC symbol), look on the
reference page for that ball number and confirm that (a) the pin name printed beside it is the
JEDEC name the LCSC symbol gives, and (b) the net printed on the same row is the one our
naming rule produces.

    .venv/bin/python -I tools/verify_ddr.py vendor/radxa_rock5b/rock5b_v1450_schematic.pdf
"""
import os
import re
import sys

import fitz  # PyMuPDF

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kicadgen as kg  # noqa: E402
from ddr_rule import dram_net  # noqa: E402

DRAM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor", "lcsc_C2920257", "part.native.kicad_sym")


def dram_pins():
    with open(DRAM, encoding="utf-8") as fh:
        return kg.symbol_pins(kg.find_all(kg.parse(fh.read()), "symbol")[0])


def main(path):
    page = fitz.open(path)[3]
    words = page.get_text("words")
    mid = page.rect.height * 0.47
    checked = name_ok = net_ok = 0
    problems = []
    for chip, channel in ((0, 0), (1, 1)):
        region = [w for w in words if (w[1] < mid) == (chip == 0)]
        for pin in dram_pins():
            half = {"a": "AC", "b": "BD"}.get(pin["name"][-1:], "??")[chip]
            net = dram_net(pin["name"], channel, half)
            if net is None:
                continue
            balls = [w for w in region if w[4] == pin["number"]]
            if not balls:
                problems.append("chip %d ball %s not found on the page" % (chip, pin["number"]))
                continue
            b = balls[0]
            row = [w for w in region if abs(w[1] - b[1]) < 3.2 and abs(w[0] - b[0]) < 130 and w is not b]
            checked += 1
            if any(w[4].lower() == pin["name"].lower() for w in row):
                name_ok += 1
            else:
                problems.append("chip %d ball %s: pin name %s not beside it" % (chip, pin["number"], pin["name"]))
            if any(w[4] == net for w in row):
                net_ok += 1
            else:
                near = sorted(set(w[4] for w in row if w[4].startswith("DDR_")))
                problems.append("chip %d ball %s (%s): expected net %s, row has %s" % (chip, pin["number"], pin["name"], net, near))
    print("signal balls checked: %d   pin name confirmed: %d   net confirmed: %d" % (checked, name_ok, net_ok))
    for p in problems[:25]:
        print("  " + p)
    return not problems


if __name__ == "__main__":
    sys.exit(0 if main(sys.argv[1]) else 1)
