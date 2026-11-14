"""Cross-check the LCSC RK3588 ball map against the Radxa Rock 5B schematic PDF.

For every ball number printed in the PDF, find the pin name printed next to it
and compare it with the name the LCSC symbol gives that ball. Two independent
sources agreeing is the evidence that the symbol's ball numbers are right.

    .venv/bin/python -I tools/verify_ballmap.py vendor/radxa_rock5b/rock5b_v1450_schematic.pdf
"""
import os
import re
import sys

import fitz  # PyMuPDF

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rk3588_symbol  # noqa: E402

BALL = re.compile(r"^(?:[A-HJ-NPRT-WY]|A[A-HJ-NPRT])\d{1,2}$")


def norm(name):
    name = name.upper().replace(" ", "")
    name = re.sub(r"^(A?VSS)_\d+$", r"\1", name)
    return name


def main(path):
    _, groups = rk3588_symbol.build_named()
    expected = {p["number"]: norm(p["name"]) for pins in groups.values() for p in pins}
    known = set(expected.values())
    verdict = {}          # ball -> ("ok" | "mismatch", pdf name, page)
    for pno, page in enumerate(fitz.open(path), start=1):
        words = page.get_text("words")
        names = [w for w in words if norm(w[4]) in known]
        if len(names) < 20:
            continue      # not a processor page
        balls = [b for b in words if BALL.match(b[4]) and b[4] in expected]
        # A pin's name is printed at a fixed vertical offset from its ball number. Rows are
        # only about 5 points apart, so calibrate that offset per page from the exact matches.
        def side(n, b):
            return "L" if n[2] <= b[0] + 1 else "R"      # name printed left or right of the ball number

        dy0 = {}
        for which in "LR":
            offsets = sorted(n[1] - b[1] for b in balls for n in names
                             if side(n, b) == which and abs(n[1] - b[1]) < 6
                             and max(n[0] - b[2], b[0] - n[2], 0) < 110 and norm(n[4]) == expected[b[4]])
            if offsets:
                dy0[which] = offsets[len(offsets) // 2]
        for b in balls:
            best = None
            for n in names:
                which = side(n, b)
                if which not in dy0 or abs((n[1] - b[1]) - dy0[which]) > 1.6:
                    continue
                gap = max(n[0] - b[2], b[0] - n[2], 0)
                if gap < 110 and (best is None or gap < best[0]):
                    best = (gap, norm(n[4]))
            if best is None:
                continue
            state = "ok" if best[1] == expected[b[4]] else "mismatch"
            if verdict.get(b[4], ("", "", 0))[0] != "ok":
                verdict[b[4]] = (state, best[1], pno)
    ok = [b for b, v in verdict.items() if v[0] == "ok"]
    bad = {b: v for b, v in verdict.items() if v[0] == "mismatch"}
    print("balls in symbol: %d   confirmed by the Rock 5B schematic: %d   disagreeing: %d   not found: %d"
          % (len(expected), len(ok), len(bad), len(expected) - len(verdict)))
    missing = sorted(set(expected) - set(verdict))
    kinds = {}
    for b in missing:
        kinds[re.sub(r"\d+", "#", expected[b].split("/")[0])] = kinds.get(re.sub(r"\d+", "#", expected[b].split("/")[0]), 0) + 1
    print("not found, by pin family: " + ", ".join("%s x%d" % kv for kv in sorted(kinds.items(), key=lambda kv: -kv[1])[:12]))
    same_rail = sum(1 for b, v in bad.items() if re.sub(r"_\d+$", "", v[1]) == re.sub(r"_\d+$", "", expected[b]))
    print("of the disagreeing balls, %d differ only in the index within the same supply rail" % same_rail)
    for b, v in sorted(bad.items(), key=lambda kv: re.sub(r"_\d+$", "", kv[1][1]) == re.sub(r"_\d+$", "", expected[kv[0]]))[:14]:
        print("  %-5s LCSC %-60s PDF p%d %s" % (b, expected[b][:60], v[2], v[1][:60]))
    return verdict, expected


if __name__ == "__main__":
    main(sys.argv[1])
