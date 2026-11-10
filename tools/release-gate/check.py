#!/usr/bin/env python3
"""heqk release gate: check every item in items.txt against its evidence.

  tools/release-gate/check.py [--validate-log FILE] [--e2e-log FILE] [--markdown OUT.md]

Exit 0 only when EVERY item passes (release ready). Items whose evidence is missing are NOT READY; items
marked blocked:/missing sign-offs are BLOCKED. Nothing here can turn an item green without the evidence.
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def check(ev, vlog, elog):
    """-> (ok, state, detail) for one evidence term."""
    kind, _, arg = ev.partition(":")
    if kind == "phase":
        if vlog is None:
            return False, "UNVERIFIED", f"{arg}: no --validate-log given"
        ok = re.search(rf"^\s*{re.escape(arg)}\s+PASS\b", vlog, re.M) is not None
        return ok, "PASS" if ok else "MISSING", f"phase {arg}"
    if kind == "e2e":
        if elog is None:
            return False, "UNVERIFIED", "no --e2e-log given"
        ok = "MC-E2E: PASS" in elog
        return ok, "PASS" if ok else "MISSING", "mc-e2e"
    if kind in ("metal", "fuzz"):  # an in-repo evidence file (metal run log / libFuzzer run log) + a regex
        path, _, rx = arg.partition(":")
        text = read(os.path.join(ROOT, path))
        if text is None:
            return False, "MISSING", f"{path} (no evidence file)"
        ok = re.search(rx, text) is not None
        return ok, "PASS" if ok else "MISSING", f"{path} ~ /{rx}/"
    if kind == "signoff":
        text = read(os.path.join(ROOT, "docs", "release", "signoffs", arg + ".md"))
        if text is None:
            return False, "BLOCKED", f"sign-off {arg} (operator decision pending)"
        appr = re.search(r"^Approved-by:\s*\S+", text, re.M)
        dec = re.search(r"^Decision:\s*\S+", text, re.M)
        ok = bool(appr and dec)
        return ok, "PASS" if ok else "BLOCKED", f"sign-off {arg}"
    if kind == "blocked":
        return False, "BLOCKED", arg
    return False, "MISSING", f"unknown evidence kind {kind!r}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate-log")
    ap.add_argument("--e2e-log")
    ap.add_argument("--markdown")
    a = ap.parse_args()
    vlog = read(a.validate_log) if a.validate_log else None
    elog = read(a.e2e_log) if a.e2e_log else None
    rows, ready = [], True
    for line in open(os.path.join(HERE, "items.txt"), encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4:
            print(f"malformed gate line: {line}", file=sys.stderr)
            return 2
        iid, area, req, evs = parts
        results = [check(e.strip(), vlog, elog) for e in evs.split(",") if e.strip()]
        ok = all(r[0] for r in results)
        state = "PASS" if ok else next(r[1] for r in results if not r[0])
        ready &= ok
        rows.append((iid, area, req, state, "; ".join(f"{r[1]} {r[2]}" for r in results)))
    w = max(len(r[0]) for r in rows)
    for iid, area, req, state, det in rows:
        print(f"{iid:<{w}}  {state:<10}  {req}")
        if state != "PASS":
            print(f"{'':<{w}}  {'':<10}  └ {det}")
    n = {s: sum(1 for r in rows if r[3] == s) for s in ("PASS", "MISSING", "UNVERIFIED", "BLOCKED")}
    verdict = "RELEASE READY" if ready else "NOT READY"
    print(f"\nRELEASE GATE: {verdict} — {n['PASS']} pass, {n['MISSING']} missing evidence, "
          f"{n['UNVERIFIED']} unverified (log not given), {n['BLOCKED']} blocked (decision / not built) of {len(rows)}")
    if a.markdown:
        with open(a.markdown, "w", encoding="utf-8") as f:
            f.write(f"# Release gate — {verdict}\n\n| Item | Area | Requirement | State | Evidence |\n|---|---|---|---|---|\n")
            for iid, area, req, state, det in rows:
                f.write(f"| {iid} | {area} | {req} | {state} | {det.replace('|', '/')} |\n")
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
