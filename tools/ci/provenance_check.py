#!/usr/bin/env python3
"""G0 driver-provenance check — every heqk driver file has a row in the register (ADR 0067 D11).

docs/security/driver-provenance.md records, per driver file, the sources it was written from
and its class (own design / permissive code / GPL behaviour reference / GPL transcription).
A driver added without a row has no recorded provenance, so this check fails until the row
exists. It checks presence only: the content of a row is a human statement, reviewed in the PR.

A file is "in the register" when its path relative to os/kernel appears in backticks, e.g.
`arch-aarch64/src/gem.rs`.
"""
import argparse
import os
import sys

DRIVER_DIRS = ("arch-aarch64/src", "hboot/src", "flashstub/src")  # flashstub: ADR 0070 (DWC2 device driver)


def driver_files(kernel_root: str) -> list:
    out = []
    for d in DRIVER_DIRS:
        base = os.path.join(kernel_root, d)
        for dirpath, _dirs, files in os.walk(base):
            for f in files:
                if f.endswith(".rs"):
                    out.append(os.path.relpath(os.path.join(dirpath, f), kernel_root).replace(os.sep, "/"))
    return sorted(out)


def missing(files: list, register_text: str) -> list:
    return [f for f in files if f"`{f}`" not in register_text]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".")
    a = ap.parse_args()
    kernel = os.path.join(a.root, "os", "kernel")
    reg = os.path.join(a.root, "docs", "security", "driver-provenance.md")
    if not os.path.isfile(reg):
        print(f"provenance: FAIL {reg} does not exist")
        return 1
    with open(reg, encoding="utf-8") as f:
        text = f.read()
    files = driver_files(kernel)
    if not files:
        print("provenance: FAIL found no driver files — refusing to call it clean")
        return 1
    gone = missing(files, text)
    if gone:
        print("provenance: FAIL driver files with no row in docs/security/driver-provenance.md:")
        for g in gone:
            print(f"  {g}")
        return 1
    print(f"provenance: ok ({len(files)} driver files, each with a register row)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
