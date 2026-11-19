#!/usr/bin/env python3
"""G2 performance ratchet — a work counter can never silently get worse (ADR 0067 D1/D2).

The heqk boot self-tests print one ` [PERF] name=value` line per work counter: a count of work
done on a fixed input (table entries examined, bytes checksummed, round trips). It is the same
number on every run and under QEMU. Timings are not work counters and are never read here.

tools/ci/baselines/perf.json maps each counter to a bound:

    {"nat_newflow_scan_max": {"max": 4096, "evidence": "..."}}

  * "max": lower is better — the run fails if the value is above the bound;
  * "min": higher is better — the run fails if the value is below the bound;
  * a counter in the baseline that the log does not print fails (a deleted counter is a
    weakened gate);
  * a counter in the log with no baseline entry fails (every counter is ratcheted).

A bound moves only by editing the baseline in a reviewed PR that names its evidence
(tools/ci/ is a protected path, tools/ci/heal/protected-paths.txt).
"""
import argparse
import json
import re
import sys

LINE = re.compile(r"\[PERF\]\s+([A-Za-z0-9_.-]+)=(\d+)\s*$")


def parse_log(text: str) -> dict:
    """The LAST value printed for each counter (validate.sh appends several boots to one log)."""
    seen = {}
    for line in text.splitlines():
        m = LINE.search(line.rstrip("\r"))
        if m:
            seen[m.group(1)] = int(m.group(2))
    return seen


def check(baseline: dict, seen: dict) -> list:
    """Return a list of failure strings; empty means the ratchet holds."""
    fails = []
    for name, bound in sorted(baseline.items()):
        kinds = [k for k in ("max", "min") if k in bound]
        if len(kinds) != 1:
            fails.append(f"{name}: baseline entry needs exactly one of 'max' / 'min'")
            continue
        if name not in seen:
            fails.append(f"{name}: in the baseline but not printed by the run")
            continue
        value, limit = seen[name], bound[kinds[0]]
        if kinds[0] == "max" and value > limit:
            fails.append(f"{name}: {value} is worse than the baseline max {limit}")
        if kinds[0] == "min" and value < limit:
            fails.append(f"{name}: {value} is worse than the baseline min {limit}")
    for name in sorted(set(seen) - set(baseline)):
        fails.append(f"{name}: printed by the run but has no baseline entry (add one)")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", required=True, help="the validate.sh QEMU log (VALIDATE_KEEP_LOG)")
    ap.add_argument("--baseline", default="tools/ci/baselines/perf.json")
    ap.add_argument("--out", help="write the parsed counters here as JSON")
    a = ap.parse_args()
    with open(a.baseline, encoding="utf-8") as f:
        baseline = json.load(f)
    with open(a.log, encoding="utf-8", errors="replace") as f:
        seen = parse_log(f.read())
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(seen, f, indent=2, sort_keys=True)
            f.write("\n")
    fails = check(baseline, seen)
    for name in sorted(seen):
        bound = baseline.get(name, {})
        print(f"  {name} = {seen[name]}  (baseline {bound.get('max', bound.get('min', '—'))})")
    if fails:
        print("perf-ratchet: FAIL")
        for f in fails:
            print(f"  {f}")
        return 1
    print(f"perf-ratchet: ok ({len(seen)} work counters within the baseline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
