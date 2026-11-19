#!/usr/bin/env python3
"""G0 SPDX check — every first-party heqk source file states its licence (ADR 0067 D11).

All HookProbe software is AGPL-3.0-only (LICENSING.md). Each Rust and assembly source file under
os/kernel must carry `SPDX-License-Identifier: AGPL-3.0-only` in its first three lines, so a file
copied out of the tree keeps its licence and a file copied IN from elsewhere stands out: a
different identifier fails here and has to be dealt with in review, not discovered later.

`--fix` adds the header to files that have none. It never rewrites a different identifier.
"""
import argparse
import os
import re
import sys

WANT = "AGPL-3.0-only"
HEADER = f"// SPDX-License-Identifier: {WANT}\n"
ID = re.compile(r"SPDX-License-Identifier:\s*(\S+)")
EXTS = (".rs", ".s", ".S")
SKIP_DIRS = {"target", ".git", "node_modules"}


def source_files(kernel_root: str) -> list:
    out = []
    for dirpath, dirs, files in os.walk(kernel_root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(files):
            if f.endswith(EXTS):
                out.append(os.path.join(dirpath, f))
    return out


def identifier(text: str):
    """The SPDX identifier in the first three lines, or None."""
    for line in text.splitlines()[:3]:
        m = ID.search(line)
        if m:
            return m.group(1)
    return None


def classify(paths: list) -> tuple:
    """(files with no header, files with a different identifier as (path, id))."""
    none, other = [], []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            ident = identifier(f.read(2048))
        if ident is None:
            none.append(p)
        elif ident != WANT:
            other.append((p, ident))
    return none, other


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--fix", action="store_true", help="add the header to files that have none")
    a = ap.parse_args()
    files = source_files(os.path.join(a.root, "os", "kernel"))
    if not files:
        print("spdx: FAIL found no source files — refusing to call it clean")
        return 1
    none, other = classify(files)
    if a.fix:
        for p in none:
            with open(p, encoding="utf-8") as f:
                body = f.read()
            with open(p, "w", encoding="utf-8") as f:
                f.write(HEADER + body)
        print(f"spdx: added the header to {len(none)} files")
        none = []
    for p in none:
        print(f"spdx: FAIL no SPDX-License-Identifier in the first three lines: {os.path.relpath(p, a.root)}")
    for p, ident in other:
        print(f"spdx: FAIL {os.path.relpath(p, a.root)} declares {ident}, not {WANT}")
    if none or other:
        return 1
    print(f"spdx: ok ({len(files)} source files declare {WANT})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
