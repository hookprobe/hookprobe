#!/usr/bin/env python3
"""G1 phase ratchet — an implemented validate.sh phase can never silently disappear (ADR 0052).

os/kernel/validate.sh carries a table of phases `"ID|marker|status(impl|plan)|stage|what"`.
validate.sh itself only fails when an *implemented* phase's PASS marker is missing — so the
cheapest way to "fix" a red QEMU gate is to flip `impl` → `plan` or delete the row. That is
exactly what an autonomous fixer (or a tired human) might do. This ratchet forbids it:

  * every ID in tools/ci/baselines/validate-phases.txt must still exist AND be `impl`;
  * new `impl` phases are welcome — `--update` rewrites the baseline (ratchet only moves up).

Downgrading a phase is a deliberate decision: edit the baseline in the same PR, where the
protected-path rule (tools/ci/heal/protected-paths.txt) puts it in front of a human.
"""
import argparse
import os
import re
import sys

ROW = re.compile(r'^\s*"([A-Za-z0-9_.+-]+)\|([^|]*)\|(impl|plan)\|')


def parse_phases(validate_sh: str) -> dict:
    phases = {}
    with open(validate_sh, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ROW.match(line)
            if m:
                phases[m.group(1)] = m.group(3)
    return phases


def read_baseline(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def check(phases: dict, baseline: list):
    """Return (errors, new_impl). Pure — unit-tested."""
    errors = []
    for pid in baseline:
        st = phases.get(pid)
        if st is None:
            errors.append(f"phase {pid} was implemented (baseline) but its row is GONE from validate.sh")
        elif st != "impl":
            errors.append(f"phase {pid} was downgraded impl -> {st}")
    new_impl = sorted(p for p, s in phases.items() if s == "impl" and p not in set(baseline))
    return errors, new_impl


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--validate", default="os/kernel/validate.sh")
    ap.add_argument("--baseline", default="tools/ci/baselines/validate-phases.txt")
    ap.add_argument("--update", action="store_true", help="raise the baseline to the current impl set")
    a = ap.parse_args()
    vs = os.path.join(a.root, a.validate)
    bl = os.path.join(a.root, a.baseline)
    phases = parse_phases(vs)
    if not phases:
        print(f"FAIL: parsed 0 phases from {vs} — table format changed? (fail-closed)")
        return 1
    baseline = read_baseline(bl)
    errors, new_impl = check(phases, baseline)
    n_impl = sum(1 for s in phases.values() if s == "impl")
    if a.update:
        if errors:
            print("refusing --update while phases regressed:\n  " + "\n  ".join(errors))
            return 1
        with open(bl, "w") as f:
            f.write("# Implemented validate.sh phases — the G1 ratchet floor (tools/ci/phase_ratchet.py).\n")
            f.write("# Only ever grows. Removing a line is a reviewed decision (protected path).\n")
            for p in sorted(p for p, s in phases.items() if s == "impl"):
                f.write(p + "\n")
        print(f"baseline updated: {n_impl} implemented phases")
        return 0
    print(f"phases: {len(phases)} total, {n_impl} impl, baseline floor {len(baseline)}")
    for e in errors:
        print(f"  RATCHET VIOLATION: {e}")
    if new_impl:
        print(f"  ratchet can move up: {len(new_impl)} new impl phase(s) {new_impl[:8]} — run with --update")
    if not baseline:
        print("FAIL: no baseline file (fail-closed) — run with --update once to create it")
        return 1
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
