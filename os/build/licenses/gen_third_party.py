#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Write THIRD_PARTY_NOTICES.md: the licence of every third-party component a heqk image can contain.

Three groups:
  1. Rust crates linked into heqk or into one of its EL0 services (the ELFs heqk embeds with include_bytes!).
     Taken from `cargo metadata --locked --all-features` for the aarch64-unknown-none-softfloat target:
     normal dependencies only (build/dev dependencies and proc-macro crates never reach the binary).
     All features, so the list covers every build flavour (a superset of any one image).
  2. The Rust core library (build-std compiles core, alloc and compiler_builtins into every heqk ELF).
  3. The JavaScript that Mission Control's built pages contain. Determined by building
     os/mission-control with source maps (2026-11-21): solid-js, plus Astro's island loader and the
     @astrojs/solid-js client. Everything else in package-lock.json is build tooling.

Firmware and the CM5 device tree sit next to the image, not in it; their records are
os/drivers/firmware/*/LICENSE.md and are linked from the output.

Licence texts come from each package's own LICENSE / COPYING / NOTICE files. For a crate offered as
"MIT OR Apache-2.0" (or similar) the MIT text is reproduced (HookProbe takes it under MIT); otherwise every
licence file is reproduced. Identical texts are printed once, with every package that uses them.

Usage (needs the crates in the cargo cache: `cargo fetch --locked` in each workspace, and
`npm ci --ignore-scripts` in os/mission-control):
  python3 os/build/licenses/gen_third_party.py            # rewrite THIRD_PARTY_NOTICES.md
  python3 os/build/licenses/gen_third_party.py --check    # exit 1 if it is out of date
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
OUT = os.path.join(ROOT, "os", "build", "licenses", "THIRD_PARTY_NOTICES.md")
KERNEL = os.path.join(ROOT, "os", "kernel")
# heqk's own workspace + every detached workspace whose ELF heqk embeds (kernel/build.rs).
WORKSPACES = [".", "el0-tlshost", "el0-wasmhost", "el0-wifi", "el0-wpa", "el0-lansvc", "el0-hsh", "tlsprov"]
TARGET = "aarch64-unknown-none-softfloat"
MC = os.path.join(ROOT, "os", "mission-control")
BROWSER_PACKAGES = ["solid-js", "astro", "@astrojs/solid-js"]
LICENCE_FILE = re.compile(r"(?i)^(licen[cs]e|copying|notice|unlicense)([-_.].*)?$")
PERMISSIVE_PICK = "MIT"

# Rust core/alloc/compiler_builtins: rust-lang/rust LICENSE-MIT (the project's COPYRIGHT file says
# copyright is retained by the contributors). Reproduced here because no cargo package carries it.
RUST_CORE_MIT = """Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""

MIT_BODY = RUST_CORE_MIT


def cargo_crates():
    crates = {}
    for ws in WORKSPACES:
        out = subprocess.run(
            ["cargo", "metadata", "--offline", "--locked", "--all-features", "--format-version", "1",
             "--filter-platform", TARGET],
            cwd=os.path.join(KERNEL, ws), capture_output=True, text=True)
        if out.returncode != 0:
            sys.exit(f"cargo metadata failed in os/kernel/{ws} (run `cargo fetch --locked` there):\n{out.stderr[-600:]}")
        meta = json.loads(out.stdout)
        pkgs = {p["id"]: p for p in meta["packages"]}
        nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
        seen, stack = set(), list(meta["workspace_members"])
        while stack:
            i = stack.pop()
            if i in seen:
                continue
            seen.add(i)
            if any("proc-macro" in t["kind"] for t in pkgs[i]["targets"]):
                continue                    # runs in the compiler; neither it nor its deps reach the binary
            for d in nodes[i]["deps"]:
                if any(k["kind"] is None for k in d["dep_kinds"]):
                    stack.append(d["pkg"])
        for i in seen:
            p = pkgs[i]
            if p["source"] is None:          # first-party path crate
                continue
            if any("proc-macro" in t["kind"] for t in p["targets"]):
                continue
            key = (p["name"], p["version"])
            entry = crates.setdefault(key, {
                "name": p["name"], "version": p["version"], "license": p["license"] or "(none declared)",
                "dir": os.path.dirname(p["manifest_path"]), "repo": p.get("repository") or "",
                "authors": p.get("authors") or [], "license_file": p.get("license_file"), "used_by": set()})
            entry["used_by"].add("heqk" if ws == "." else ws)
    return crates


def npm_packages():
    lock = json.load(open(os.path.join(MC, "package-lock.json")))["packages"]
    out = []
    for name in BROWSER_PACKAGES:
        meta = lock.get(f"node_modules/{name}")
        if meta is None:
            sys.exit(f"{name} is not in os/mission-control/package-lock.json")
        d = os.path.join(MC, "node_modules", name)
        if not os.path.isdir(d):
            sys.exit(f"{d} missing: run `npm ci --ignore-scripts` in os/mission-control")
        out.append({"name": name, "version": meta["version"], "license": meta.get("license", "(none declared)"),
                    "dir": d, "repo": f"https://www.npmjs.com/package/{name}", "authors": [], "license_file": None,
                    "used_by": {"mission-control (browser)"}})
    return out


def licence_texts(pkg):
    """[(filename, text)] to reproduce for this package."""
    d = pkg["dir"]
    files = sorted(f for f in os.listdir(d) if LICENCE_FILE.match(f) and os.path.isfile(os.path.join(d, f)))
    if pkg.get("license_file"):
        files = [pkg["license_file"]]
    lic = pkg["license"].replace("/", " OR ")
    if " OR " in lic and PERMISSIVE_PICK in re.split(r"[ ()]+", lic):
        mit = [f for f in files if re.search(r"(?i)mit", f)]
        notice = [f for f in files if re.match(r"(?i)notice", f)]
        if mit:
            files = mit + notice
        elif len(files) == 1:
            pass  # a single combined file (e.g. LICENSE holding both texts): keep it
    texts = []
    for f in files:
        with open(os.path.join(d, f), encoding="utf-8", errors="replace") as fh:
            texts.append((f, fh.read().strip() + "\n"))
    if not texts:
        # No licence file in the published package. Reproduce the standard text of the licence taken,
        # with the copyright holders as the package metadata names them (marked as such).
        holders = ", ".join(pkg["authors"]) or "the authors listed at " + pkg["repo"]
        texts.append(("(no licence file in the package; standard MIT text, holders from Cargo.toml `authors`)",
                      f"Copyright (c) {holders}\n\n" + MIT_BODY))
    return texts


def render(crates, npm):
    rows, groups = [], {}
    def add(pkg, kind):
        texts = licence_texts(pkg)
        body = "\n".join(f"--- {name} ---\n{text}" for name, text in texts)
        h = hashlib.sha256(body.encode()).hexdigest()[:12]
        groups.setdefault(h, {"body": body, "pkgs": []})["pkgs"].append(f"{pkg['name']} {pkg['version']}")
        rows.append((kind, pkg["name"], pkg["version"], pkg["license"], ", ".join(sorted(pkg["used_by"])), h))
    for key in sorted(crates):
        add(crates[key], "Rust crate")
    for p in npm:
        add(p, "JavaScript")
    core = {"name": "Rust core library (core, alloc, compiler_builtins)", "version": "nightly-2026-07-20",
            "license": "MIT OR Apache-2.0", "used_by": {"every heqk ELF (build-std)"}}
    body = "--- rust-lang/rust LICENSE-MIT ---\nCopyright (c) The Rust Project Developers\n\n" + RUST_CORE_MIT
    h = hashlib.sha256(body.encode()).hexdigest()[:12]
    groups.setdefault(h, {"body": body, "pkgs": []})["pkgs"].append(core["name"])
    rows.append(("Rust toolchain", core["name"], core["version"], core["license"], "every heqk ELF (build-std)", h))

    licences = {}
    for r in rows:
        licences[r[3]] = licences.get(r[3], 0) + 1
    o = []
    o.append("<!-- Generated by os/build/licenses/gen_third_party.py. Do not edit; rerun the script. -->")
    o.append("# Third-party notices for the heqk image\n")
    o.append("heqk and Mission Control are HookProbe software under AGPL-3.0-only (see `LICENSING.md`). A heqk image")
    o.append("also contains the third-party components below, each under its own licence. All of them are")
    o.append("permissive (MIT, Apache-2.0, BSD, ISC, 0BSD, Unicode) and compatible with AGPL-3.0.\n")
    o.append("The list is the union over every build flavour (`--all-features`) of heqk and the EL0 services it")
    o.append("embeds, so any one image contains a subset of it. Files that sit **next to** the image on the boot")
    o.append("partition have their own records:\n")
    o.append("- CM5 device tree (GPL-2.0, with its source): [`os/drivers/firmware/rpi-dtb/LICENSE.md`](../../drivers/firmware/rpi-dtb/LICENSE.md)")
    o.append("- CYW43455 Wi-Fi firmware (Cypress licence; NVRAM GPL-2.0): [`os/drivers/firmware/brcm-firmware-rpt/LICENSE.md`](../../drivers/firmware/brcm-firmware-rpt/LICENSE.md)\n")
    o.append("## Licences in use\n")
    o.append("| Licence expression | Components |")
    o.append("|---|---|")
    for lic, n in sorted(licences.items(), key=lambda x: (-x[1], x[0])):
        o.append(f"| `{lic}` | {n} |")
    o.append(f"\n## Components ({len(rows)})\n")
    o.append("| Kind | Name | Version | Licence | Linked into | Text |")
    o.append("|---|---|---|---|---|---|")
    for kind, name, ver, lic, used, h in rows:
        o.append(f"| {kind} | {name} | {ver} | `{lic}` | {used} | [{h}](#text-{h}) |")
    o.append("\n## Licence texts\n")
    o.append("Where a component is offered under a choice of licences that includes MIT, HookProbe takes it under")
    o.append("MIT and the MIT text is reproduced.\n")
    for h, g in sorted(groups.items(), key=lambda x: sorted(x[1]["pkgs"])[0].lower()):
        o.append(f'<a id="text-{h}"></a>\n### Text {h}\n')
        o.append("Used by: " + ", ".join(sorted(g["pkgs"], key=str.lower)) + "\n")
        o.append("````text\n" + g["body"].rstrip("\n") + "\n````\n")
    return "\n".join(o)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    text = render(cargo_crates(), npm_packages())
    if a.check:
        cur = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if cur != text:
            print("third-party notices: OUT OF DATE (rerun os/build/licenses/gen_third_party.py)")
            return 1
        print("third-party notices: up to date")
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(OUT, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
