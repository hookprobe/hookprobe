#!/usr/bin/env python3
"""Release-identity check (gate g0): every HookProbe version agrees with os/kernel/hal/src/release.rs.

The release identity (display version, codename, SemVer) lives in hal::release and is what the device reports
(boot banner, /api/system, hsh version). This check fails when any of these disagree with its SEMVER:
  - the [package] version of every Cargo.toml in the repository,
  - the "version" of every package.json outside legacy/ (and its package-lock.json root entries),
  - the version of every local (source-less) package in every Cargo.lock,
and when the release note docs/releases/v<VERSION>.md is missing.

Usage: python3 -I tools/ci/release_check.py [--root DIR]
"""
import argparse
import json
import os
import re
import sys

SKIP_DIRS = {"target", "node_modules", ".git", ".claude"}


def release_identity(root):
    src = open(os.path.join(root, "os/kernel/hal/src/release.rs"), encoding="utf-8").read()

    def const(name):
        m = re.search(rf'^pub const {name}: &str = "([^"]*)";$', src, re.M)
        if not m:
            raise SystemExit(f"release_check: {name} not found in hal/src/release.rs")
        return m.group(1)

    return const("VERSION"), const("CODENAME"), const("SEMVER")


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        yield dirpath, filenames


def package_version(cargo_toml_text):
    lines = cargo_toml_text.split("\n")
    try:
        s = next(i for i, l in enumerate(lines) if l.strip() == "[package]")
    except StopIteration:
        return None
    for l in lines[s + 1:]:
        if re.match(r"^\s*\[", l):
            return None
        m = re.match(r'^\s*version\s*=\s*"([^"]*)"', l)
        if m:
            return m.group(1)
    return None


def check(root):
    version, codename, semver = release_identity(root)
    problems = []
    for dirpath, filenames in walk(root):
        rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if "Cargo.toml" in filenames:
            v = package_version(open(os.path.join(dirpath, "Cargo.toml"), encoding="utf-8").read())
            if v is not None and v != semver:
                problems.append(f"{rel}/Cargo.toml: version {v} != {semver}")
        if "Cargo.lock" in filenames:
            text = open(os.path.join(dirpath, "Cargo.lock"), encoding="utf-8").read()
            for block in text.split("\n[[package]]\n")[1:]:
                if re.search(r"^source = ", block, re.M):
                    continue
                name = re.search(r'^name = "([^"]*)"', block, re.M)
                ver = re.search(r'^version = "([^"]*)"', block, re.M)
                if name and ver and ver.group(1) != semver:
                    problems.append(f"{rel}/Cargo.lock: {name.group(1)} {ver.group(1)} != {semver}")
        if "package.json" in filenames and not (rel + "/").startswith("legacy/"):
            pkg = json.load(open(os.path.join(dirpath, "package.json"), encoding="utf-8"))
            if pkg.get("version") != semver:
                problems.append(f"{rel}/package.json: version {pkg.get('version')} != {semver}")
            lock = os.path.join(dirpath, "package-lock.json")
            if os.path.exists(lock):
                lk = json.load(open(lock, encoding="utf-8"))
                for where, v in (("top", lk.get("version")), ('packages[""]', lk.get("packages", {}).get("", {}).get("version"))):
                    if v != semver:
                        problems.append(f"{rel}/package-lock.json {where}: version {v} != {semver}")
    note = os.path.join(root, "docs", "releases", f"v{version}.md")
    if not os.path.exists(note):
        problems.append(f"docs/releases/v{version}.md: release note missing")
    return (version, codename, semver), problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".")
    a = ap.parse_args(argv)
    (version, codename, semver), problems = check(a.root)
    for p in problems:
        print(f"  {p}")
    print(f"release check: HookProbe OS v{version} \"{codename}\" (SemVer {semver}): {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
