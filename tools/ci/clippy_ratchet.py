#!/usr/bin/env python3
"""G1 clippy ratchet for the heqk kernel workspace (ADR 0048).

heqk has never been clippy-clean (~230 findings at ADR 0048 time), so `-D warnings` would be
permanently red and therefore ignored. A ratchet is the honest gate instead:

  * count clippy/rustc findings per (crate, lint) for our own crates;
  * FAIL if any (crate, lint) count rises above tools/ci/baselines/clippy.json, or a new
    (crate, lint) pair appears, or any finding is error-level;
  * when counts fall, print it — `--update` lowers the baseline (it can only go down
    unless a human edits the protected baseline file).

So every PR leaves heqk no worse, every cleanup is locked in, and no one has to fix 230
warnings before the gate becomes useful.
"""
import argparse
import collections
import json
import os
import subprocess
import sys

OUR_CRATES = {"kernel", "hal", "arch_aarch64", "abi", "hboot", "boot_abi"}


def collect(lines) -> tuple:
    """Parse cargo --message-format=json lines → (Counter[(crate,lint)], errors list). Pure."""
    counts = collections.Counter()
    errors = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") != "compiler-message":
            continue
        crate = (m.get("target") or {}).get("name", "?").replace("-", "_")
        if crate not in OUR_CRATES:
            continue
        msg = m.get("message") or {}
        level = msg.get("level")
        code = (msg.get("code") or {}).get("code") or ""
        if level not in ("warning", "error") or not code:
            continue  # summaries ("N warnings emitted") carry no code
        spans = msg.get("spans") or []
        prim = next((s for s in spans if s.get("is_primary")), spans[0] if spans else {})
        if "/out/" in (prim.get("file_name") or ""):
            continue  # build-script generated code
        counts[(crate, code)] += 1
        if level == "error":
            errors.append(f"{crate}: {code} at {prim.get('file_name')}:{prim.get('line_start')}")
    return counts, errors


def compare(counts, baseline: dict) -> tuple:
    """→ (violations, improvements). Pure."""
    viol, impr = [], []
    for (crate, lint), n in sorted(counts.items()):
        b = baseline.get(crate, {}).get(lint, 0)
        if n > b:
            viol.append(f"{crate}: {lint} {b} -> {n} (+{n - b})")
    for crate, lints in baseline.items():
        for lint, b in lints.items():
            n = counts.get((crate, lint), 0)
            if n < b:
                impr.append(f"{crate}: {lint} {b} -> {n}")
    return viol, impr


def to_baseline(counts) -> dict:
    out = collections.defaultdict(dict)
    for (crate, lint), n in sorted(counts.items()):
        out[crate][lint] = n
    return dict(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--baseline", default="tools/ci/baselines/clippy.json")
    ap.add_argument("--features", default="netsvc")
    ap.add_argument("--from-json", help="parse a saved cargo json log instead of running clippy (tests)")
    ap.add_argument("--update", action="store_true")
    a = ap.parse_args()
    bl_path = os.path.join(a.root, a.baseline)
    if a.from_json:
        with open(a.from_json) as f:
            lines = f.readlines()
    else:
        tr = os.environ.get("CI_TARGET_ROOT")
        tgt = os.path.join(tr, "clippy") if tr else os.path.join(a.root, "os/kernel/target/ci-clippy")
        env = dict(os.environ, CARGO_TARGET_DIR=tgt)
        p = subprocess.run(
            ["cargo", "clippy", "-p", "kernel", "--features", a.features, "--message-format=json"],
            cwd=os.path.join(a.root, "os/kernel"), env=env, capture_output=True, text=True)
        lines = p.stdout.splitlines()
        if p.returncode != 0 and not any('"level":"error"' in l for l in lines):
            print(p.stderr[-3000:])
            print("FAIL: clippy did not run (toolchain/build failure, not a lint) — fail-closed")
            return 1
    counts, errors = collect(lines)
    total = sum(counts.values())
    if a.update:
        if errors:
            print("refusing --update with error-level findings:\n  " + "\n  ".join(errors))
            return 1
        with open(bl_path, "w") as f:
            json.dump({"_comment": "clippy ratchet floor (tools/ci/clippy_ratchet.py) — counts may only go DOWN",
                       "total": total, **to_baseline(counts)}, f, indent=1, sort_keys=True)
            f.write("\n")
        print(f"baseline written: {total} findings")
        return 0
    if not os.path.exists(bl_path):
        print("FAIL: no clippy baseline (fail-closed) — run with --update once")
        return 1
    with open(bl_path) as f:
        baseline = {k: v for k, v in json.load(f).items() if isinstance(v, dict)}
    viol, impr = compare(counts, baseline)
    print(f"clippy findings: {total} (baseline {sum(sum(v.values()) for v in baseline.values())})")
    for e in errors:
        print(f"  ERROR-LEVEL: {e}")
    for v in viol:
        print(f"  RATCHET VIOLATION: {v}")
    if impr:
        print(f"  improved ({len(impr)}): {impr[:6]}{' ...' if len(impr) > 6 else ''} — lock it in with --update")
    return 1 if (viol or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
