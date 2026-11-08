#!/usr/bin/env python3
"""L2 heal loop — deterministic failure classifier (ADR 0052).

Turns a red gate log into ONE decision the rest of the loop can act on:

    rerun    transient infra (network, runner, QEMU-on-TCG budget) — retry, don't "fix" code
    autofix  a code-level failure an agent may attempt (build error, failing test, reachable
             vulnerable dependency, new clippy finding, e2e/QEMU phase regression)
    human    anything that is a DECISION, not a defect: a leaked secret (rotate!), a licence
             or policy rejection, CI wiring, a downgraded phase, an unknown failure

Deterministic regex rules, first match wins, ordered by severity. No model is involved in
classification — the AI only ever sees failures this file has already routed to `autofix`
(C9: AI proposes, the gates decide). Every decision carries a stable `signature` so the same
failure is tracked by one issue and one attempt budget, never a storm of duplicates.

    classify.py out/ci/gate-results.json          (local: gates.sh output)
    classify.py --log path/to/job.log [--gate g4] (CI: a downloaded job log)
"""
import argparse
import hashlib
import json
import os
import re
import sys

# (category, action, gate-hint or None, [regexes]) — ORDER MATTERS (first match wins).
RULES = [
    ("secret_leak", "human", "secrets", [
        r"SECRET TRIPWIRE", r"leaks? found", r"WRN leaks found", r"Secret detected"]),
    ("vulnerable_dependency", "autofix", "g4", [
        r"error\[vulnerability\]", r"found \d+ (?:high|critical) severity vulnerabilit",
        r"\b\d+ (?:high|critical)\b.*vulnerabilit"]),
    ("supply_chain_policy", "human", "g4", [
        r"error\[(?:rejected|unlicensed|unmaintained|banned|wildcard|source-not-allowed|unsound|notice)\]",
        r"failed to satisfy license requirements"]),
    ("ci_wiring", "human", "g0", [r"FAIL: W[1-7] "]),
    ("shell_lint", "autofix", "g0", [r"\bSC\d{4} \((?:error|warning)\)"]),
    ("phase_downgrade", "human", "g1", [r"RATCHET VIOLATION: phase \S+ (?:was downgraded|.*GONE)"]),
    ("clippy_regression", "autofix", "g1", [r"RATCHET VIOLATION: \w+: ", r"ERROR-LEVEL: "]),
    ("toolchain_env", "human", None, [
        r"is not installed for the toolchain", r"can't find crate for `(?:core|std)`",
        r"required tool '\S+' not installed", r"command not found",
        r"\.\.\. skip \(no [\w./ -]+",  r"No such file or directory.*qemu"]),
    ("infra_transient", "rerun", None, [
        r"Could not resolve host", r"Connection (?:reset|refused|timed out)", r"ETIMEDOUT|ECONNRESET|EAI_AGAIN",
        r"\b(?:502|503|504) (?:Bad Gateway|Service Unavailable|Gateway Time-out)",
        r"API rate limit exceeded", r"The runner has received a shutdown signal",
        r"No space left on device", r"failed to download", r"spurious network error",
        r"The operation was canceled"]),
    ("qemu_budget", "rerun", "g2", [r"TIMEOUT after \d+s", r"qemu.*timed out"]),
    ("build_error", "autofix", None, [
        r"error\[E\d{4}\]", r"error: could not compile", r"GAP: build broken", r"UI build failed"]),
    ("test_failure", "autofix", "g1", [r"test result: FAILED", r"panicked at "]),
    ("qemu_phase_regression", "autofix", "g2", [r"VERDICT: REGRESSION", r"FAIL — (?:verifier|WiFi crypto KAT)"]),
    ("e2e_failure", "autofix", "g3", [r"MC-E2E: FAIL", r"^\s+FAIL\s{2}\S"]),
]

_NOISE = [
    (re.compile(r"\x1b\[[0-9;]*m"), ""),                                  # ANSI colour
    (re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z\s*"), ""),                    # GH log timestamps
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "0x?"),
    (re.compile(r"\b\d+(\.\d+)?s\b"), "?s"),                              # durations
    (re.compile(r"/tmp/[\w.-]+"), "/tmp/?"),
    (re.compile(r"\(\d+\)"), "(?)"),                                      # thread ids
    (re.compile(r"\s+"), " "),
]


def normalize(line: str) -> str:
    s = line
    for rx, rep in _NOISE:
        s = rx.sub(rep, s)
    return s.strip()


def classify_text(text: str, gate_hint: str = None) -> dict:
    """Pure: log text → decision dict. Unit-tested against fixtures."""
    lines = text.splitlines()
    for cat, action, gate, pats in RULES:
        rxs = [re.compile(p, re.M) for p in pats]
        hits = [l for l in lines if any(r.search(l) for r in rxs)]
        if not hits:
            continue
        evidence = [normalize(h)[:300] for h in hits[:12]]
        ids = sorted(set(re.findall(r"\b(RUSTSEC-\d{4}-\d{4}|GHSA-[\w-]{14}|CVE-\d{4}-\d{4,})\b", text)))
        if cat == "vulnerable_dependency" and not ids:
            ids = sorted(set(re.findall(r"ID: (\S+)", text)))
        key = "|".join(sorted(set(evidence[:5]))) + "|" + ",".join(ids)
        return {
            "category": cat,
            "action": action,
            "fixable": action == "autofix",
            "gate": gate_hint or gate or "?",
            "signature": f"{cat}-" + hashlib.sha256(key.encode()).hexdigest()[:12],
            "ids": ids,
            "evidence": evidence,
            "hits": len(hits),
        }
    return {"category": "unknown", "action": "human", "fixable": False, "gate": gate_hint or "?",
            "signature": "unknown-" + hashlib.sha256("\n".join(normalize(l) for l in lines[-20:]).encode()).hexdigest()[:12],
            "ids": [], "evidence": [normalize(l)[:300] for l in lines[-12:] if l.strip()], "hits": 0}


def classify_results(path: str) -> list:
    with open(path) as f:
        doc = json.load(f)
    out = []
    for g in doc.get("gates", []):
        if g.get("status") != "fail":
            continue
        log = g.get("log", "")
        text = open(log, errors="replace").read() if os.path.exists(log) else ""
        out.append(classify_text(text, g["gate"]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="?", help="gate-results.json from tools/ci/gates.sh")
    ap.add_argument("--log", action="append", default=[], help="raw log file (repeatable)")
    ap.add_argument("--gate", help="gate hint for --log")
    ap.add_argument("--out", help="write decisions JSON here")
    a = ap.parse_args()
    decisions = []
    if a.results:
        decisions += classify_results(a.results)
    for lp in a.log:
        decisions.append(classify_text(open(lp, errors="replace").read(), a.gate))
    if not decisions:
        print("no failing gates to classify")
    for d in decisions:
        print(f"[{d['gate']}] {d['category']} -> {d['action'].upper()}  sig={d['signature']} ids={d['ids']}")
        for e in d["evidence"][:4]:
            print(f"      {e}")
    if a.out:
        with open(a.out, "w") as f:
            json.dump(decisions, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
