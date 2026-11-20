#!/usr/bin/env python3
"""G6 metal timing ratchet — a CM5 timing can never silently get worse (ADR 0067 D1/D2).

At AP boot heqk prints two benchmark lines, timed with the generic timer on the real core:

  [IDS-BENCH] packet::verdict ns/pkt (...): tcp-data-1400=342 tcp-ack=335 ... | mix avg=322 ns -> ...
  [IDS-TIERS] tcp-data ns per tier: parse=11 l2-stateful=30 ... l4-rules=52 | sum=304

This tool reads them from one or more console logs (one log per boot), takes the MEDIAN of each
value across the boots, and compares it with tools/ci/baselines/perf-metal.json:

    {"tolerance_pct": 8, "min_boots": 3,
     "timings": {"ids.mix": {"max_ns": 441, "evidence": "..."}}}

  * a median above `max_ns * (1 + tolerance_pct/100)` fails (boot-to-boot spread is about 5 %);
  * a timing in the baseline that no log printed fails;
  * fewer boots than `min_boots` fails, unless --allow-fewer-boots (then the result is printed
    as INDICATIVE and the exit status is still 0 only if nothing regressed);
  * values with no baseline entry are printed, never fail: add them to the baseline deliberately.

Give it CM5 console logs only: QEMU timing is never evidence, and this tool cannot tell the two
apart. A baseline moves only by a reviewed commit that names its evidence file under
docs/design/metal-evidence/. It is run by hand on a bench batch's logs for now; wiring it into the
g6 metal gate waits for that gate's log layout.
"""
import argparse
import json
import re
import statistics
import sys

BENCH = re.compile(r"\[IDS-BENCH\].*?:\s*(.*?)\|\s*mix avg=(\d+)\s*ns")
TIERS = re.compile(r"\[IDS-TIERS\].*?:\s*(.*?)\|\s*sum=(\d+)")
PAIR = re.compile(r"([A-Za-z0-9_.-]+)=(\d+)")


def parse_boot(text: str) -> dict:
    """Timings of ONE boot log: the last [IDS-BENCH] and [IDS-TIERS] lines in it."""
    out = {}
    for line in text.splitlines():
        m = BENCH.search(line)
        if m:
            for k, v in PAIR.findall(m.group(1)):
                out[f"ids.{k}"] = int(v)
            out["ids.mix"] = int(m.group(2))
        m = TIERS.search(line)
        if m:
            for k, v in PAIR.findall(m.group(1)):
                out[f"tier.{k}"] = int(v)
            out["tier.sum"] = int(m.group(2))
    return out


def medians(boots: list) -> dict:
    """Median per timing over the boots that printed it."""
    keys = sorted({k for b in boots for k in b})
    return {k: statistics.median([b[k] for b in boots if k in b]) for k in keys}


def check(baseline: dict, med: dict) -> list:
    tol = baseline.get("tolerance_pct", 8)
    fails = []
    for name, bound in sorted(baseline.get("timings", {}).items()):
        if name not in med:
            fails.append(f"{name}: in the baseline but not printed by any boot")
            continue
        limit = bound["max_ns"] * (1 + tol / 100.0)
        if med[name] > limit:
            fails.append(f"{name}: median {med[name]:g} ns is above {bound['max_ns']} ns + {tol} % ({limit:.1f})")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logs", nargs="+", help="CM5 console logs, one per boot")
    ap.add_argument("--baseline", default="tools/ci/baselines/perf-metal.json")
    ap.add_argument("--allow-fewer-boots", action="store_true")
    a = ap.parse_args()
    with open(a.baseline, encoding="utf-8") as f:
        baseline = json.load(f)
    boots = []
    for path in a.logs:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        b = parse_boot(text)
        if b:
            boots.append(b)
        else:
            print(f"metal-timing: note: {path} has no [IDS-BENCH] / [IDS-TIERS] line")
    if not boots:
        print("metal-timing: FAIL no boot printed a benchmark line")
        return 1
    med = medians(boots)
    for name in sorted(med):
        bound = baseline.get("timings", {}).get(name)
        print(f"  {name} = {med[name]:g} ns  (baseline {bound['max_ns'] if bound else '—'})")
    need = baseline.get("min_boots", 3)
    fails = check(baseline, med)
    few = len(boots) < need
    if few and not a.allow_fewer_boots:
        fails.append(f"{len(boots)} boot(s) given, the baseline requires {need} (median of boots)")
    if fails:
        print("metal-timing: FAIL")
        for f in fails:
            print(f"  {f}")
        return 1
    tag = f"INDICATIVE ({len(boots)} boot(s), {need} required for a gate result)" if few else f"ok ({len(boots)} boots)"
    print(f"metal-timing: {tag}; {len(baseline.get('timings', {}))} timings within the baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
