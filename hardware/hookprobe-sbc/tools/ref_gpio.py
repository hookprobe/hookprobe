"""List what the Radxa Rock 5B reference connects to each RK3588 GPIO and system ball.

    .venv/bin/python -I tools/ref_gpio.py vendor/radxa_rock5b/rock5b_v1450_schematic.pdf
"""
import os
import re
import sys

import fitz  # PyMuPDF

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rk3588_symbol  # noqa: E402

UNITS = ["GPIO bank 0", "GPIO bank 1", "GPIO bank 2", "GPIO bank 3", "GPIO bank 4", "System"]
BALL = re.compile(r"^[A-Z]{1,2}\d{1,2}$")


def extract(path):
    """Return {ball: (unit, pin name, page, [words on the same row])}."""
    _, groups = rk3588_symbol.build_named()
    doc = fitz.open(path)
    pages = {p: doc[p - 1].get_text("words") for p in range(10, 20)}
    out = {}
    for unit in UNITS:
        for pin in groups[unit]:
            gid = re.search(r"GPIO\d_[A-D]\d", pin["name"])
            key = gid.group(0) if gid else pin["name"].split("/")[0]
            best = None
            for pno, words in pages.items():
                for b in words:
                    if b[4] != pin["number"]:
                        continue
                    row = [w for w in words if abs(w[1] - b[1]) < 4.2 and abs(w[0] - b[0]) < 200 and w is not b]
                    if any(key.upper() in w[4].upper() for w in row):
                        nets = [w[4] for w in sorted(row, key=lambda w: w[0])
                                if key.upper() not in w[4].upper() and not BALL.match(w[4]) and len(w[4]) > 2]
                        best = (unit, pin["name"], pno, nets)
            out[pin["number"]] = best or (unit, pin["name"], None, [])
    return out


if __name__ == "__main__":
    data = extract(sys.argv[1])
    for unit in UNITS:
        print("== " + unit)
        rows = sorted((v[1], k, v) for k, v in data.items() if v[0] == unit)
        for name, ball, v in rows:
            gid = re.search(r"GPIO\d_[A-D]\d", name)
            short = gid.group(0) if gid else name
            print("  %-10s %-5s p%-3s %s" % (short, ball, v[2], " ".join(v[3])[:110]))
