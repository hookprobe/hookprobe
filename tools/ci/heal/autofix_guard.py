#!/usr/bin/env python3
"""L2 heal loop — the autofix guard (ADR 0048). Deterministic; runs on EVERY autofix diff.

An autonomous fixer is only safe if "make the gate green" can never be achieved by
weakening the gate. This guard rejects an autofix change that:

  A1  touches a protected path (tools/ci/heal/protected-paths.txt: the gate machinery,
      secret/supply-chain policy, signing + keys, ADRs/governance)
  A2  removes more tests / assertions / PASS markers than it adds, in any file
  A3  adds a suppression: #[ignore], #[allow(...)], continue-on-error, `|| true`,
      skipped tests, `cfg(any())` / `cfg(FALSE)` dead-gating, `--no-verify`
  A4  is too big to review (default > 400 changed lines or > 15 files)
  A5  is not on an `autofix/*` branch (when --require-branch)
  A6  edits a gate PASS-marker emitter (`[Pxx] PASS`, `MC-E2E: PASS`): the phase gates grep text
      the code under test prints, so an agent must never change what "pass" looks like
  A7  changes a file the diff cannot show as text (binary, symlink, submodule/gitlink) — the
      guard cannot judge what it cannot read

Pass = the change MAY be proposed (draft PR) — a human still merges (Red tier).

SCOPE (security-auditor, 2026-11-08): while an agent can execute code (cargo/python/build.rs),
this guard stops accidents and naive gaming, NOT an adversary. The adversarial boundary is the
JOB SPLIT in autoheal.yml: the agent job holds no write token, the re-gate job holds no
secrets, and the propose job re-runs THIS guard from a clean default-branch checkout.

    autofix_guard.py --base origin/main [--head HEAD] [--require-branch]
    autofix_guard.py --diff saved.patch                 (tests / offline)
"""
import argparse
import fnmatch
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_LINES = int(os.environ.get("AUTOFIX_MAX_LINES", "400"))
MAX_FILES = int(os.environ.get("AUTOFIX_MAX_FILES", "15"))

TESTLIKE = re.compile(
    r"#\[test\]|#\[test_case\]|\bassert(?:_eq|_ne|_matches)?!|\bdebug_assert|\bassert\s*\(|\bassert\s+\S"
    r"|\bexpect\(|\bit\(|\btest\(|\bok \"|\bbad \"|\|impl\|")
SUPPRESS = re.compile(
    r"#\[ignore\b|#!?\[allow\(|continue-on-error|\|\|\s*true\b|\b(?:it|describe|test)\.skip\b"
    r"|@pytest\.mark\.skip|unittest\.skip|cfg\(any\(\)\)|cfg\(FALSE\)|--no-verify|# *noqa|eslint-disable"
    r"|\bxfail\b|SKIP_GATE|HEQK_SKIP"
    # lint suppression outside attributes (Cargo [lints] tables, rustflags -A, cfg_attr(..allow..))
    r"|^\s*\[(?:workspace\.)?lints\b|cfg_attr\([^)]*allow|rustflags|RUSTFLAGS|\s-A\s*(?:clippy|warnings|dead_code)"
    # dependency redirection (cargo-deny's sources policy also catches git deps)
    r"|^\s*\[patch[.\]]|^\s*\[replace\]"
    # a commented-out assertion is a deleted assertion that A2 would count as "moved"
    r"|^\s*(?://|#|/\*|\*)\s*(?:debug_)?assert")
PASS_MARKER = re.compile(r"\[P[\w.+-]*\]\s*PASS|MC-E2E:\s*PASS|\bok\(\"|VERDICT:")
BAD_MODE = re.compile(r"^(?:new file mode|new mode|deleted file mode|old mode) (120000|160000)")


def load_protected(path=os.path.join(HERE, "protected-paths.txt")):
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def is_protected(path, protected):
    for p in protected:
        if path == p or (p.endswith("/") and path.startswith(p)) or fnmatch.fnmatch(path, p):
            return True
    return False


UNPARSED = "<unparseable diff header>"


def parse_diff(diff_text):
    """Unified diff → {path: {"add": [lines], "del": [lines]}}. Pure.

    BOTH sides of every file header are recorded: a rename/copy of a protected file to an
    unprotected name (`a/tools/ci/deny.toml b/x.toml`) must still trip A1 — checking only the
    new path would let an agent delete a gate's policy by renaming it away. A header we cannot
    parse becomes the UNPARSED pseudo-path, which evaluate() rejects (fail-closed).
    """
    files, cur = {}, None

    def touch(p):
        files.setdefault(p, {"add": [], "del": [], "flags": set()})

    for line in diff_text.splitlines():
        if cur is not None and BAD_MODE.match(line):
            files[cur]["flags"].add("symlink/submodule")
        if cur is not None and line.startswith(("Binary files", "GIT binary patch")):
            files[cur]["flags"].add("binary")
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            if m:
                touch(m.group(1))
                cur = m.group(2)
            else:
                cur = UNPARSED
            touch(cur)
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            touch(line.split(" ", 2)[2])
        elif cur is None or line.startswith(("+++", "---", "@@", "index ", "new file", "deleted file",
                                              "similarity", "dissimilarity", "old mode", "new mode",
                                              "Binary files", "GIT binary patch", "literal ", "delta ")):
            continue
        elif line.startswith("+"):
            files[cur]["add"].append(line[1:])
        elif line.startswith("-"):
            files[cur]["del"].append(line[1:])
    return files


def evaluate(files, protected, branch=None, require_branch=False):
    """→ list of violations (empty = pass). Pure — unit-tested."""
    v = []
    if require_branch and not (branch or "").startswith("autofix/"):
        v.append(f"A5 branch '{branch}' is not autofix/* — the guard only clears autofix branches")
    total = 0
    for path, ch in sorted(files.items()):
        total += len(ch["add"]) + len(ch["del"])
        if path == UNPARSED:
            v.append("A1 a diff header could not be parsed (quoted/odd path) — fail-closed")
            continue
        if is_protected(path, protected):
            v.append(f"A1 touches protected path {path}")
        for fl in sorted(ch.get("flags", ())):
            v.append(f"A7 {path}: {fl} change — not reviewable as text")
        if any(PASS_MARKER.search(l) for l in ch["add"] + ch["del"]):
            v.append(f"A6 {path}: edits a gate PASS-marker line — what 'pass' looks like is human-only")
        rm = sum(1 for l in ch["del"] if TESTLIKE.search(l))
        ad = sum(1 for l in ch["add"] if TESTLIKE.search(l))
        if rm > ad:
            v.append(f"A2 {path}: removes {rm} test/assert/PASS line(s), adds {ad} (net weakening)")
        for l in ch["add"]:
            if SUPPRESS.search(l):
                v.append(f"A3 {path}: adds a suppression: {l.strip()[:120]}")
    if total > MAX_LINES:
        v.append(f"A4 {total} changed lines > {MAX_LINES} (too big to review; split it)")
    if len(files) > MAX_FILES:
        v.append(f"A4 {len(files)} files > {MAX_FILES}")
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--diff", help="read a saved unified diff instead of running git")
    ap.add_argument("--branch", help="branch name (default: current)")
    ap.add_argument("--require-branch", action="store_true")
    ap.add_argument("--protected", default=os.path.join(HERE, "protected-paths.txt"),
                    help="TRUSTED protected-path list. Callers must pass the copy from the base "
                         "branch / operator checkout, never the one inside the change under review.")
    a = ap.parse_args()
    if a.diff:
        text = open(a.diff).read()
        branch = a.branch
    else:
        mb = subprocess.run(["git", "merge-base", a.base, a.head], capture_output=True, text=True)
        if mb.returncode != 0:
            print(f"FAIL: cannot find merge-base of {a.base} and {a.head} (fail-closed): {mb.stderr.strip()}")
            return 1
        # --no-renames: a rename is shown as delete + add, so BOTH paths are policy-checked.
        # --text: a `.gitattributes` `-diff` entry must not turn source changes into "Binary files
        # differ" and blind A2/A3/A4; real binaries then still trip A7 via the mode/binary checks.
        text = subprocess.run(["git", "-c", "core.quotePath=false", "-c", "core.attributesFile=/dev/null",
                               "diff", "--no-color", "--no-renames", "--text",
                               "--no-ext-diff", "--no-textconv", mb.stdout.strip(), a.head],
                              capture_output=True, text=True, check=True).stdout
        branch = a.branch or os.environ.get("GITHUB_HEAD_REF") or subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True).stdout.strip()
    files = parse_diff(text)
    if not a.diff:
        # Binary detection independent of --text (numstat prints "-\t-\t<path>" for binaries, and
        # honours a planted `-diff` attribute — which then ALSO trips A7).
        ns = subprocess.run(["git", "diff", "--numstat", "--no-renames", mb.stdout.strip(), a.head],
                            capture_output=True, text=True, check=True).stdout
        for line in ns.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3 and parts[0] == "-" and parts[1] == "-":
                files.setdefault(parts[2], {"add": [], "del": [], "flags": set()})["flags"].add("binary")
    if not files:
        print("FAIL: empty diff — an autofix must change something (fail-closed)")
        return 1
    v = evaluate(files, load_protected(a.protected), branch, a.require_branch)
    n = sum(len(c["add"]) + len(c["del"]) for c in files.values())
    print(f"autofix guard: {len(files)} file(s), {n} changed line(s), branch={branch}")
    for x in v:
        print(f"  BLOCK {x}")
    print("  PASS — may be proposed as a draft PR (a human merges)" if not v else "  REJECTED")
    return 1 if v else 0


if __name__ == "__main__":
    sys.exit(main())
