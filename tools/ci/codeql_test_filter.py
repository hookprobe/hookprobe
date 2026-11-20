#!/usr/bin/env python3
"""Drop CodeQL results that sit in Rust TEST code, between `analyze` and `upload-sarif` (.github/workflows/codeql.yml).

Why: CodeQL's Rust extractor does not know `#[cfg(test)]`, so every test vector in a unit test is reported as a
"Critical" hard-coded cryptographic value (alerts #1316-#1368: all false positives, dismissed by hand one by one).
Test DIRECTORIES are excluded by `paths-ignore` (.github/codeql/codeql-config.yml); inline test code needs this.

Two rules, deliberately different in scope:

  1. Items under `#[cfg(test)]` / `#[cfg(all(test, ..))]` / `#[test]` are never compiled into a device image, so
     results there are dropped for EVERY rule. That includes whole FILES whose `mod` declaration is under such an
     attribute (`#[cfg(test)] mod testutil;`), directly or through a test-only parent module.
  2. On-device known-answer self-tests DO ship in test builds, so only `rust/hard-coded-cryptographic-value` is
     dropped there (their fixed vectors are public test vectors); every other rule still sees them. A self-test is
     a `fn ...selftest...`, a `mod ...selftest...` block, or an item under `#[cfg(feature = "...selftest...")]`
     (e.g. export.rs's `#[cfg(feature = "securechannel-selftest")] mod selftest`, #1372 — a feature the shipping
     guard keeps out of every device image).

Everything removed is printed (rule, file:line, why), so the CI log shows exactly what the filter hid.

    codeql_test_filter.py <sarif file or dir> [--root REPO]
"""
import argparse
import functools
import json
import os
import re
import sys

CRYPTO_RULE = "rust/hard-coded-cryptographic-value"
TEST_ATTR = re.compile(r"#\[\s*(?:cfg\s*\(\s*(?:all\s*\(\s*)?test\b|test\s*\])")
SELFTEST_FN = re.compile(r"\bfn\s+\w*(?:selftest|self_test)\w*\s*[<(]")
SELFTEST_MOD = re.compile(r"\bmod\s+\w*(?:selftest|self_test)\w*\s*(?=\{)")  # stop BEFORE the brace: _block_end counts it
SELFTEST_FEATURE = re.compile(r"#\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?feature\s*=\s*\"[^\"]*(?:selftest|self-test)[^\"]*\"")


def _mask(src: str) -> str:
    """Blank out comments, string / raw-string / byte-string and char literals (keeping newlines), so brace
    matching only sees code. Lifetimes ('a) are left alone."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j): depth += 1; j += 2
                elif src.startswith("*/", j): depth -= 1; j += 2
                else: j += 1
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        elif re.match(r"b?r#*\"", src[i:i + 40]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r"b?r(#*)\"", src[i:])
            end = src.find('"' + m.group(1), i + m.end())
            j = n if end < 0 else end + 1 + len(m.group(1))
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        elif c == '"' or (c == "b" and src.startswith('b"', i) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        elif c == "'":
            m = re.match(r"b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'])'", src[i:])
            if m:
                out.append(" " * m.end()); i += m.end()
            else:
                out.append(c); i += 1  # a lifetime
        else:
            out.append(c); i += 1
    return "".join(out)


def _block_end(code: str, start: int):
    """Offset just past the item that begins at `start`: its `{...}` body, or the `;` of a body-less item."""
    depth = 0
    for j in range(start, len(code)):
        ch = code[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        elif ch == ";" and depth == 0:
            return j + 1
    return None


def test_ranges(src: str):
    """[(first_line, last_line, kind)] — kind 'test' (cfg(test) / #[test] item) or 'selftest' (an on-device KAT fn)."""
    code = _mask(src)
    line_at = lambda off: code.count("\n", 0, off) + 1
    out = []
    for rx, kind in ((TEST_ATTR, "test"), (SELFTEST_FN, "selftest"), (SELFTEST_MOD, "selftest")):
        for m in rx.finditer(code):
            end = _block_end(code, m.end())
            if end:
                out.append((line_at(m.start()), line_at(end), kind))
    # the feature NAME is a string literal, which _mask blanks: match the raw source, but only where the masked
    # text still has the '#' (so a match inside a comment or string does not count); offsets are identical
    for m in SELFTEST_FEATURE.finditer(src):
        if code[m.start()] != "#":
            continue
        close = code.find("]", m.end())
        end = _block_end(code, close + 1) if close >= 0 else None
        if end:
            out.append((line_at(m.start()), line_at(end), "selftest"))
    return out


@functools.lru_cache(maxsize=None)
def _read(path: str):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


@functools.lru_cache(maxsize=None)
def _file_facts(path: str):
    """(masked source, test ranges) of a file, computed once (kernel main.rs is ~15k lines)."""
    src = _read(path)
    if src is None:
        return None, []
    return _mask(src), test_ranges(src)


def _declaring_files(path: str):
    """Files that may hold the `mod <name>;` declaring `path` (Rust 2018 module layout): for src/a/x.rs that is
    src/a.rs or src/a/mod.rs; for a file next to the crate root, lib.rs / main.rs / mod.rs in the same dir."""
    d, base = os.path.split(path)
    name = os.path.splitext(base)[0]
    if name in ("lib", "main"):
        return name, []
    if name == "mod":  # src/a/mod.rs is declared as `mod a;` one level up
        d, name = os.path.split(d)
    parent = d + ".rs"
    return name, [os.path.join(d, f) for f in ("lib.rs", "main.rs", "mod.rs")] + [parent]


def test_only_file(path: str, _depth: int = 0) -> bool:
    """True when the whole file only compiles for tests: its `mod <name>;` declaration sits under #[cfg(test)]
    (e.g. `#[cfg(test)] mod testutil;`), directly or through a test-only parent module."""
    if _depth > 8:
        return False
    name, candidates = _declaring_files(path)
    decl = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+" + re.escape(name) + r"\s*;", re.M)
    for c in candidates:
        if os.path.abspath(c) == os.path.abspath(path):
            continue
        masked, ranges = _file_facts(os.path.abspath(c))
        if masked is None:
            continue
        m = decl.search(masked)
        if not m:
            continue
        line = masked.count("\n", 0, m.start()) + 1
        if any(a <= line <= b and k == "test" for a, b, k in ranges):
            return True
        return test_only_file(c, _depth + 1)  # declared here: test-only iff this file is
    return False


def filter_sarif(doc: dict, root: str, log=print) -> int:
    cache, whole, dropped = {}, {}, 0
    for run in doc.get("runs", []):
        kept = []
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 0)
            why = None
            if uri.endswith(".rs") and line:
                p = os.path.join(root, uri)
                if uri not in cache:
                    src = _read(p) if os.path.isfile(p) else None
                    cache[uri] = test_ranges(src) if src is not None else []
                    whole[uri] = src is not None and test_only_file(p)
                if whole[uri]:
                    why = "file declared under #[cfg(test)] (test-only module)"
                for a, b, kind in ([] if why else cache[uri]):
                    if a <= line <= b and (kind == "test" or r.get("ruleId") == CRYPTO_RULE):
                        why = "#[cfg(test)]/#[test] item" if kind == "test" else "on-device self-test (crypto-constant rule only)"
                        break
            if why:
                dropped += 1
                log(f"  dropped {r.get('ruleId')} {uri}:{line} — {why}")
            else:
                kept.append(r)
        run["results"] = kept
    return dropped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif", help="a .sarif file or a directory of them (filtered in place)")
    ap.add_argument("--root", default=".")
    a = ap.parse_args()
    files = [os.path.join(a.sarif, f) for f in sorted(os.listdir(a.sarif)) if f.endswith(".sarif")] \
        if os.path.isdir(a.sarif) else [a.sarif]
    if not files:
        print(f"codeql_test_filter: no .sarif under {a.sarif}", file=sys.stderr)
        return 1
    for f in files:
        with open(f) as fh:
            doc = json.load(fh)
        n = filter_sarif(doc, a.root)
        with open(f, "w") as fh:
            json.dump(doc, fh)
        print(f"codeql_test_filter: {os.path.basename(f)}: {n} result(s) in test code dropped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
