#!/usr/bin/env python3
"""G0 — the CI wiring meta-gate (ADR 0048): "a gate that is not wired is not a gate".

The 2026-11-07 repo merge silently un-wired CI: gate-ladder.yml was parked under
legacy/, and os/kernel/.github/{dependabot.yml,workflows/} kept existing in a place
GitHub never reads. Nothing failed — protection just quietly stopped. This gate makes
that class of regression loud. It checks:

  W1  no live .github/ outside the repo root (GitHub ignores nested ones) unless allow-listed
  W2  every root workflow parses, declares top-level `permissions`, pins every action
      (@vN / @<sha>, never @main/@master/@latest), never uses `pull_request_target`, and
      never lets a `pull_request` reach a self-hosted (metal) runner
  W3  every script a workflow runs from tools/ci or os/ exists
  W4  every live Cargo.lock / package-lock.json is listed in tools/ci/lockfiles.txt (G4 scope)
  W5  the root dependabot.yml covers every listed lockfile dir + github-actions
  W6  every gate of the ladder is wired into at least one workflow
  W7  the autofix protected-path list covers the gate machinery itself

Stdlib + PyYAML (present on GitHub runners and Debian/Ubuntu system python).
"""
import argparse
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # fail-closed: never silently skip the meta-gate
    print("FAIL: PyYAML not importable (python3-yaml)")
    sys.exit(1)

# Nested .github dirs that are deliberately inert. Everything under legacy/ is frozen (ADR 0047).
ALLOWED_NESTED_GITHUB = {
    "os/kernel/tools/usbboot/.github": "vendored upstream raspberrypi/usbboot — inert by design",
}
SKIP_DIRS = {".git", "node_modules", "target", "out", ".claude", "dist"}

# W6: gate -> regex that must match the text of at least one root workflow.
REQUIRED_WIRING = {
    "g0 hygiene/wiring": r"gates\.sh\s+[^\n]*\bg0\b",
    "g1 static+unit": r"gates\.sh\s+[^\n]*\bg1\b",
    "g2 QEMU validate": r"validate\.sh|gates\.sh\s+[^\n]*\bg2\b",
    "g3 mc-e2e": r"gates\.sh\s+[^\n]*\bg3\b|mc-e2e\.sh",
    "g4 supply chain": r"gates\.sh\s+[^\n]*\bg4\b",
    "g4r reproducibility": r"gates\.sh\s+[^\n]*\bg4r\b",
    "g6 metal": r"gates\.sh\s+[^\n]*\bg6\b",
    "secrets scan": r"gitleaks",
    "heal loop (workflow_run on failure)": r"workflow_run",
    "autofix guard": r"autofix_guard\.py",
}
PROTECTED_MUST_COVER = [".github/workflows/", "tools/ci/", ".gitleaks.toml", "os/kernel/validate.sh"]
PIN_OK = re.compile(r"@(v\d+(\.\d+)*|[0-9a-f]{40})$")
# dtolnay/rust-toolchain encodes the TOOLCHAIN in the ref by design (@stable / @nightly / @1.96.0).
TOOLCHAIN_REF_OK = re.compile(r"^dtolnay/rust-toolchain@(stable|beta|nightly(-\d{4}-\d\d-\d\d)?|\d+\.\d+(\.\d+)?)$")


def walk_nested_github(root):
    found = []
    for dp, dns, _ in os.walk(root):
        rel = os.path.relpath(dp, root)
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        if rel.startswith("legacy"):
            dns[:] = []
            continue
        if ".github" in dns and rel != ".":
            found.append(os.path.normpath(os.path.join(rel, ".github")))
    return found


def live_lockfiles(root):
    out = []
    for dp, dns, fns in os.walk(root):
        rel = os.path.relpath(dp, root)
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        if rel.split(os.sep)[0] in ("legacy", "docs"):
            dns[:] = []
            continue
        for fn in fns:
            if fn in ("Cargo.lock", "package-lock.json"):
                out.append(("cargo" if fn == "Cargo.lock" else "npm", os.path.normpath(rel)))
    return sorted(out)


def read_lockfile_list(path):
    items = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                eco, d = line.split()
                items.append((eco, os.path.normpath(d)))
    return items


def workflow_triggers(doc):
    on = doc.get("on", doc.get(True))  # YAML 1.1 parses a bare `on:` key as boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on.keys())
    return set()


SHA_PIN = re.compile(r"@[0-9a-f]{40}$")


def _writes(perms):
    if isinstance(perms, str):
        return perms == "write-all"
    if isinstance(perms, dict):
        return any(v == "write" for v in perms.values())
    return False


def job_is_privileged(doc, job):
    """A job is privileged if it can write (job or inherited workflow permissions) or references a
    secret other than the default GITHUB_TOKEN (W2b, security-auditor M4)."""
    perms = job.get("permissions", doc.get("permissions"))
    blob = json.dumps(job)
    other_secrets = [s for s in re.findall(r"secrets\.(\w+)", blob) if s != "GITHUB_TOKEN"]
    return _writes(perms) or bool(other_secrets)


def check_workflow(name, text):
    """Return list of errors for one workflow. Pure — unit-tested."""
    errs = []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return [f"{name}: YAML parse error: {e}"]
    if not isinstance(doc, dict):
        return [f"{name}: not a mapping"]
    trig = workflow_triggers(doc)
    if not trig:
        errs.append(f"{name}: no `on:` triggers")
    if "pull_request_target" in trig:
        errs.append(f"{name}: uses pull_request_target (runs fork code with secrets) — forbidden")
    if "permissions" not in doc:
        errs.append(f"{name}: no top-level `permissions:` (token would default to broad scope)")
    jobs = doc.get("jobs") or {}
    if not jobs:
        errs.append(f"{name}: no jobs")
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            errs.append(f"{name}:{jid}: job is not a mapping")
            continue
        if "runs-on" not in job and "uses" not in job:
            errs.append(f"{name}:{jid}: neither runs-on nor uses")
        ro = job.get("runs-on", "")
        ro_s = " ".join(ro) if isinstance(ro, list) else str(ro)
        if "self-hosted" in ro_s and ({"pull_request", "pull_request_target"} & trig):
            errs.append(f"{name}:{jid}: self-hosted (metal) runner reachable from pull_request — forbidden")
        refs = [job["uses"]] if isinstance(job.get("uses"), str) else []
        for st in job.get("steps") or []:
            if isinstance(st, dict) and isinstance(st.get("uses"), str):
                refs.append(st["uses"])
        privileged = job_is_privileged(doc, job)
        for u in refs:
            if u.startswith("./") or u.startswith("docker://"):
                continue
            if privileged and not SHA_PIN.search(u):
                errs.append(f"{name}:{jid}: holds a secret/write token, so every action must be pinned to a "
                            f"full commit SHA (W2b; a moved tag would run with those privileges): {u}")
            elif not PIN_OK.search(u) and not TOOLCHAIN_REF_OK.match(u):
                errs.append(f"{name}:{jid}: action not pinned to a version/sha: {u}")
    return errs


def script_refs(text):
    return sorted(set(re.findall(r"\b((?:tools/ci|os/kernel/tools|os/build)/[\w./-]+\.(?:sh|py))\b", text)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    errs, notes = [], []

    # W1
    for g in walk_nested_github(root):
        if g in ALLOWED_NESTED_GITHUB:
            notes.append(f"W1 allow-listed nested {g}: {ALLOWED_NESTED_GITHUB[g]}")
        else:
            errs.append(f"W1 nested {g}/ is never read by GitHub — move its workflows/dependabot to the root .github/")

    # W2 + W3
    wdir = os.path.join(root, ".github", "workflows")
    wf_texts = {}
    for fn in sorted(os.listdir(wdir)) if os.path.isdir(wdir) else []:
        if fn.endswith((".yml", ".yaml")):
            with open(os.path.join(wdir, fn)) as f:
                wf_texts[fn] = f.read()
    if not wf_texts:
        errs.append("W2 no workflows in .github/workflows")
    for fn, text in wf_texts.items():
        errs += [f"W2 {e}" for e in check_workflow(fn, text)]
        for ref in script_refs(text):
            if not os.path.exists(os.path.join(root, ref)):
                errs.append(f"W3 {fn} runs {ref} which does not exist")

    # W4
    lf_path = os.path.join(root, "tools/ci/lockfiles.txt")
    listed = read_lockfile_list(lf_path) if os.path.exists(lf_path) else []
    live = live_lockfiles(root)
    for eco, d in live:
        if (eco, d) not in listed:
            errs.append(f"W4 {eco} lockfile in {d} is not in tools/ci/lockfiles.txt — G4 would never scan it")
    for eco, d in listed:
        if (eco, d) not in live:
            errs.append(f"W4 tools/ci/lockfiles.txt lists {eco} {d} but no lockfile exists there")

    # W5
    dpath = os.path.join(root, ".github", "dependabot.yml")
    if not os.path.exists(dpath):
        errs.append("W5 no root .github/dependabot.yml")
    else:
        with open(dpath) as f:
            dep = yaml.safe_load(f) or {}
        covered = set()
        for u in dep.get("updates") or []:
            eco = u.get("package-ecosystem")
            dirs = u.get("directories") or [u.get("directory", "/")]
            for d in dirs:
                covered.add((eco, os.path.normpath(d.strip("/")) if d.strip("/") else "."))
        if not any(e == "github-actions" for e, _ in covered):
            errs.append("W5 dependabot does not cover github-actions")
        for eco, d in listed:
            if (eco, d) not in covered:
                errs.append(f"W5 dependabot does not cover {eco} {d}")

    # W6
    alltext = "\n".join(wf_texts.values())
    for gate, rx in REQUIRED_WIRING.items():
        if not re.search(rx, alltext):
            errs.append(f"W6 gate '{gate}' is not wired into any workflow")

    # W7
    pp = os.path.join(root, "tools/ci/heal/protected-paths.txt")
    if not os.path.exists(pp):
        errs.append("W7 tools/ci/heal/protected-paths.txt missing")
    else:
        with open(pp) as f:
            prot = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for must in PROTECTED_MUST_COVER:
            if not any(must.startswith(p) or p == must for p in prot):
                errs.append(f"W7 protected-paths.txt does not protect {must}")

    for n in notes:
        print(f"  note: {n}")
    for e in errs:
        print(f"  FAIL: {e}")
    print(f"G0 wiring: {len(wf_texts)} workflows, {len(listed)} lockfiles, {len(errs)} problem(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
