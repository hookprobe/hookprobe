#!/usr/bin/env python3
"""gen_oui — build OUI.TXT (discovery D3) from the IEEE MA-L registry.

  gen_oui.py SOURCE OUT.TXT

SOURCE is either the IEEE CSV (https://standards-oui.ieee.org/oui/oui.csv: Registry,Assignment,Organization
Name,Organization Address) or an nmap-mac-prefixes style file ("AABBCC Vendor" per line, e.g.
/usr/share/nmap/nmap-mac-prefixes). Only 24-bit MA-L assignments are kept; vendor names are made printable
ASCII-safe UTF-8, collapsed whitespace, capped at 96 bytes; output is sorted and unique by prefix — exactly what
the kernel loader (kernel/src/oui.rs) accepts. Sign the result with `policy-sign.py sign-oui`.
"""
import csv, io, re, sys


def rows(path):
    raw = open(path, "rb").read().decode("utf-8", "replace")
    head = raw[:200]
    if head.startswith("Registry,") or "Assignment" in head.split("\n", 1)[0]:
        for r in csv.DictReader(io.StringIO(raw)):
            if r.get("Registry", "MA-L") == "MA-L":
                yield r["Assignment"].strip(), r["Organization Name"]
    else:
        for line in raw.splitlines():
            m = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
            if m:
                yield m.group(1), m.group(2)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, out = sys.argv[1], sys.argv[2]
    best = {}
    for p, name in rows(src):
        p = p.upper()
        if not re.fullmatch(r"[0-9A-F]{6}", p):
            continue
        name = re.sub(r"\s+", " ", "".join(c for c in name if c.isprintable())).strip()
        enc = name.encode("utf-8")[:96]
        name = enc.decode("utf-8", "ignore").strip()
        if name and p not in best:
            best[p] = name
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# HookProbe OUI pack — IEEE MA-L registry, {len(best)} assignments (os/build/fpgen/gen_oui.py)\n")
        for p in sorted(best):
            f.write(f"{p} {best[p]}\n")
    print(f"{out}: {len(best)} assignments, {len(set(best.values()))} distinct vendors")


if __name__ == "__main__":
    main()
