#!/usr/bin/env python3
"""Drop CodeQL results that sit in Rust TEST code, between `analyze` and `upload-sarif` (.github/workflows/codeql.yml).

Why: CodeQL's Rust extractor does not know `#[cfg(test)]`, so every test vector in a unit test is reported as a
"Critical" hard-coded cryptographic value (alerts #1316-#1368: all false positives, dismissed by hand one by one).
Test DIRECTORIES are excluded by `paths-ignore` (.github/codeql/codeql-config.yml); inline test code needs this.

Two rules, deliberately different in scope:

  1. Items under `#[cfg(test)]` / `#[cfg(all(test, ..))]` / `#[test]` are never compiled into a device image, so
     results there are dropped for EVERY rule.
  2. On-device known-answer self-tests (`fn ...selftest...`) DO ship, so only `rust/hard-coded-cryptographic-value`
     is dropped there (their fixed vectors are public test vectors); every other rule still sees them.

Everything removed is printed (rule, file:line, why), so the CI log shows exactly what the filter hid.

    codeql_test_filter.py <sarif file or dir> [--root REPO]
"""
import argparse
import json
import os
import re
import sys

CRYPTO_RULE = "rust/hard-coded-cryptographic-value"
TEST_ATTR = re.compile(r"#\[\s*(?:cfg\s*\(\s*(?:all\s*\(\s*)?test\b|test\s*\])")
SELFTEST_FN = re.compile(r"\bfn\s+\w*(?:selftest|self_test)\w*\s*[<(]")


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
    for rx, kind in ((TEST_ATTR, "test"), (SELFTEST_FN, "selftest")):
        for m in rx.finditer(code):
            end = _block_end(code, m.end())
            if end:
                out.append((line_at(m.start()), line_at(end), kind))
    return out


def filter_sarif(doc: dict, root: str, log=print) -> int:
    cache, dropped = {}, 0
    for run in doc.get("runs", []):
        kept = []
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 0)
            why = None
            if uri.endswith(".rs") and line:
                if uri not in cache:
                    p = os.path.join(root, uri)
                    cache[uri] = []
                    if os.path.isfile(p):
                        with open(p, encoding="utf-8", errors="replace") as fh:
                            cache[uri] = test_ranges(fh.read())
                for a, b, kind in cache[uri]:
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
