#!/usr/bin/env python3
"""G1 clippy ratchet for the heqk kernel workspace (ADR 0052).

heqk has never been clippy-clean (~230 findings at ADR 0052 time), so `-D warnings` would be
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
import tempfile

OUR_CRATES = {"kernel", "hal", "arch_aarch64", "abi", "hboot", "boot_abi"}


def collect(lines, featureset="") -> tuple:
    """Parse cargo --message-format=json lines → (Counter[(crate[@featureset],lint)], errors). Pure."""
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
        key = f"{crate}@{featureset}" if featureset else crate
        counts[(key, code)] += 1
        if level == "error":
            errors.append(f"{crate}@{featureset}: {code} at {prim.get('file_name')}:{prim.get('line_start')}")
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


def run_clippy(src_root, featuresets, target_root):
    """Lint `src_root`/os/kernel once per feature set → (Counter, errors) or raise RuntimeError.

    One pass per feature set: `netsvc` alone never compiles the Mission Control server (mcserve /
    mctls — the device's HTTPS stack). Counts are keyed `<crate>@<featureset>`. Callers must give
    base and head DIFFERENT target roots (see main) — a shared one replays cached diagnostics."""
    stub_ui = tempfile.mkdtemp(prefix="heqk-lint-ui-")   # lint needs *a* UI dist, not the real one
    with open(os.path.join(stub_ui, "index.html"), "w") as f:
        f.write("<!doctype html><title>lint</title>\n")
    counts, errors = collections.Counter(), []
    for fs in featuresets:
        env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(target_root, "clippy-" + fs), HEQK_UI_DIST=stub_ui)
        p = subprocess.run(["cargo", "clippy", "-p", "kernel", "--features", fs, "--message-format=json"],
                           cwd=os.path.join(src_root, "os/kernel"), env=env, capture_output=True, text=True)
        got = p.stdout.splitlines()
        if p.returncode != 0 and not any('"level":"error"' in l for l in got):
            raise RuntimeError(f"clippy [{fs}] did not run (toolchain/build failure, not a lint):\n{p.stderr[-3000:]}")
        c, e = collect(got, fs)
        counts.update(c)
        errors += e
    return counts, errors


def git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)


def resolve_base(root, against):
    """The commit to compare against: explicit ref, or `auto` = CI_BASE_REF / origin/main merge-base /
    HEAD~1. None → fall back to the stored baseline file."""
    if against == "none":
        return None
    if against != "auto":
        r = git(root, "rev-parse", "--verify", against + "^{commit}")
        return r.stdout.strip() or None
    head = git(root, "rev-parse", "HEAD").stdout.strip()
    for ref in [os.environ.get("CI_BASE_REF"), "origin/main"]:
        if ref and git(root, "rev-parse", "-q", "--verify", ref).returncode == 0:
            mb = git(root, "merge-base", ref, "HEAD").stdout.strip()
            if mb and mb != head:
                return mb
    r = git(root, "rev-parse", "-q", "--verify", "HEAD~1")
    return r.stdout.strip() or None


def export_tree(root, sha):
    """Materialise `os/` at `sha` into a temp dir via `git archive` — read-only on the repository."""
    d = tempfile.mkdtemp(prefix="heqk-clippy-base-")
    arc = subprocess.Popen(["git", "-C", root, "archive", sha, "os"], stdout=subprocess.PIPE)
    tar = subprocess.run(["tar", "-x", "-C", d], stdin=arc.stdout, capture_output=True)
    arc.stdout.close()
    if arc.wait() != 0 or tar.returncode != 0:
        raise RuntimeError(f"git archive {sha} failed: {tar.stderr.decode()[-500:]}")
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--baseline", default="tools/ci/baselines/clippy.json")
    ap.add_argument("--features", default="netsvc;mcserve",
                    help="';'-separated feature sets, each linted separately (mcserve = MC server + HTTPS)")
    ap.add_argument("--against", default="auto",
                    help="compare with this git ref linted by the SAME toolchain (auto | <ref> | none). heqk "
                         "floats on nightly, so a stored count drifts whenever clippy adds a lint (CI 2026-11-08: "
                         "needless_range_loop 12→18 on a newer nightly, no code change).")
    ap.add_argument("--from-json", help="parse a saved cargo json log instead of running clippy (tests)")
    ap.add_argument("--update", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    bl_path = os.path.join(root, a.baseline)
    fsets = a.features.split(";")
    tr = os.environ.get("CI_TARGET_ROOT") or os.path.join(root, "os/kernel/target/ci")
    if a.from_json:
        with open(a.from_json) as f:
            counts, errors = collect(f.readlines())
    else:
        try:
            counts, errors = run_clippy(root, fsets, tr)
        except RuntimeError as e:
            print(f"FAIL: {e} — fail-closed")
            return 1
    total = sum(counts.values())

    base = None if (a.update or a.from_json) else resolve_base(root, a.against)
    if base:
        try:
            bdir = export_tree(root, base)
            # SEPARATE target dir for the base — never share it with the head. Cargo hashes workspace
            # path-crates relative to the workspace root, so base and head `hal` are the SAME unit, and
            # git-archive mtimes (commit time) look "fresh": cargo then REPLAYS the head's cached
            # diagnostics for the base and every comparison reads equal (caught by a negative test).
            bcounts, _ = run_clippy(bdir, fsets, os.path.join(tr, "base"))
        except RuntimeError as e:
            print(f"FAIL: could not lint the base {base[:12]}: {e} — fail-closed")
            return 1
        base_doc = to_baseline(bcounts)
        viol, impr = compare(counts, base_doc)
        print(f"clippy findings: head {total} vs base {base[:12]} {sum(bcounts.values())} (same toolchain)")
        for v in viol:
            print(f"  RATCHET VIOLATION (new vs base): {v}")
        if impr:
            print(f"  improved ({len(impr)}): {impr[:6]}{' ...' if len(impr) > 6 else ''}")
        return 1 if viol else 0
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
