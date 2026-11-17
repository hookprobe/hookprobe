#!/usr/bin/env python3
"""G4 npm audit with reviewed, expiring exceptions (tools/ci/npm-audit-exceptions.txt).

`npm audit --audit-level=high` has no way to record a reviewed decision, so an advisory with NO patched release
(GHSA-fc5q-39xc-vjpf, picomatch <= 4.0.7, 2026-11-17: the latest release is still vulnerable) keeps the gate red
with nothing anyone can do, and npm's only "fix" is a major downgrade. This wrapper keeps the gate strict:

  * every high/critical advisory FAILS unless it is listed in the exceptions file;
  * a listed exception stops counting once its expiry date has passed;
  * a listed exception stops counting as soon as the advisory publishes a patched version (checked against the
    GitHub advisory database) — then the fix is to upgrade, not to keep the exception.

Exceptions file: one per line, `GHSA-id | package | YYYY-MM-DD expiry | reason` ('#' comments). Like
tools/ci/deny.toml's ignore list, every entry needs a reason a reviewer can check.

    npm_audit_gate.py <dir>                       (runs `npm audit --omit=dev --json` there)
    npm_audit_gate.py <dir> --audit-json FILE     (tests / offline)
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EXCEPTIONS = os.path.join(HERE, "npm-audit-exceptions.txt")
FAIL_LEVELS = {"high", "critical"}
GHSA = re.compile(r"GHSA-[\w]{4}-[\w]{4}-[\w]{4}")


def load_exceptions(path=EXCEPTIONS):
    out = {}
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 4 or not GHSA.fullmatch(parts[0]) or not parts[3]:
                raise ValueError(f"{path}:{n}: want 'GHSA-id | package | YYYY-MM-DD | reason'")
            out[parts[0]] = {"package": parts[1], "expires": datetime.date.fromisoformat(parts[2]), "reason": parts[3]}
    return out


def root_advisories(audit: dict):
    """{GHSA: (package, severity, title)} for every advisory npm reports at high/critical (the root causes:
    `via` entries that are objects; string `via` entries are just packages depending on them)."""
    out = {}
    for pkg, v in audit.get("vulnerabilities", {}).items():
        for via in v.get("via", []):
            if isinstance(via, dict) and via.get("severity") in FAIL_LEVELS:
                m = GHSA.search(via.get("url", ""))
                key = m.group(0) if m else f"{via.get('name', pkg)}:{via.get('source')}"
                out[key] = (via.get("name", pkg), via["severity"], via.get("title", ""))
    return out


def patched_version(ghsa: str):
    """The advisory's first patched version for npm, None if there is none, or 'unknown' if the lookup failed."""
    req = urllib.request.Request(f"https://api.github.com/advisories/{ghsa}",
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "hookprobe-ci"})
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
    except Exception:
        return "unknown"
    vers = [v.get("first_patched_version") for v in d.get("vulnerabilities", [])
            if v.get("package", {}).get("ecosystem") == "npm"]
    return next((p for p in vers if p), None)


def decide(advisories: dict, exceptions: dict, today: datetime.date, patched=patched_version):
    """-> (failures, accepted): lists of human-readable lines."""
    failures, accepted = [], []
    for ghsa, (pkg, sev, title) in sorted(advisories.items()):
        ex = exceptions.get(ghsa)
        if not ex:
            failures.append(f"{ghsa} {pkg} ({sev}): {title} — not in npm-audit-exceptions.txt")
            continue
        if today > ex["expires"]:
            failures.append(f"{ghsa} {pkg} ({sev}): exception EXPIRED {ex['expires']} — re-review or upgrade")
            continue
        p = patched(ghsa)
        if p not in (None, "unknown"):
            failures.append(f"{ghsa} {pkg} ({sev}): a patched release exists ({pkg} {p}) — upgrade; the exception no longer applies")
            continue
        note = " (patch status not checked: advisory lookup failed)" if p == "unknown" else ""
        accepted.append(f"{ghsa} {pkg} ({sev}): accepted until {ex['expires']} — {ex['reason']}{note}")
    return failures, accepted


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--audit-json")
    a = ap.parse_args()
    if a.audit_json:
        with open(a.audit_json) as f:
            audit = json.load(f)
    else:
        p = subprocess.run(["npm", "audit", "--omit=dev", "--json"], cwd=a.dir, capture_output=True, text=True)
        try:
            audit = json.loads(p.stdout)
        except json.JSONDecodeError:
            print(f"npm audit produced no JSON (exit {p.returncode}):\n{p.stderr[-2000:]}")
            return 1
        if "error" in audit:
            print(f"npm audit failed: {audit['error']}")
            return 1
    failures, accepted = decide(root_advisories(audit), load_exceptions(), datetime.date.today())
    for line in accepted:
        print(f"  accepted  {line}")
    for line in failures:
        print(f"  FAIL      {line}")
    n = len(failures)
    print(f"npm audit {a.dir}: {n} high/critical advisory(ies) not covered by a valid exception" if n
          else f"npm audit {a.dir}: clean (high+), {len(accepted)} reviewed exception(s) in force")
    if n:
        print(f"found {n} high severity vulnerabilities")  # the line the heal classifier keys on (vulnerable_dependency)
    return 1 if n else 0


if __name__ == "__main__":
    sys.exit(main())
