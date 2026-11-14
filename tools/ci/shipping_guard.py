#!/usr/bin/env python3
"""Shipping-flavour guard (W4, task #55): no development-only surface can enter the shipping build.

The shipping feature set is `tools/ci/shipping-features.txt` (the one source of truth for CI, release and the
factory). Cargo features are additive and imply others, so a check of the LIST alone is not enough: this resolves
every crate's enabled features for that set (`cargo tree --format '{p} |{f}|'`) and fails when any development-only
feature of ANY crate in the graph is active — a bench transport, a debug shell extra, a seeded test path, a
self-rebooting or manufacturing-only build, a bench diagnostic.

    tools/ci/shipping_guard.py                    resolve with cargo (run from anywhere in the repo)
    tools/ci/shipping_guard.py --tree FILE        check a saved `cargo tree --format '{p} |{f}|'` output (tests)
    tools/ci/shipping_guard.py --features a,b     check another set (e.g. a factory override)

Exit 0 = clean, 1 = a forbidden feature is active (each one named, with the path that enables it), 2 = usage /
resolution error (fail-closed: an unresolvable set is never "clean").
"""
import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Development-only features (any crate in the kernel's graph). Keep in step with the BENCH ONLY / never-shipped
# notes in os/kernel/kernel/Cargo.toml and os/kernel/arch-aarch64/Cargo.toml.
FORBIDDEN = {
    "hsh-dev": "development shell extras",
    "securechannel-selftest": "seeded / deterministic secure-channel entropy and test keys",
    "securechannel-host-responder": "seeded responder static (host PoP / responder-sim only)",
    "wpa3probe": "WPA3 feasibility probe (bench)",
    "wifi-pmkid-noexpire": "PMKID never-expire bench mode (REL-08)",
    "p15-bench": "eMMC write self-tests that clobber production LBAs",
    "crashtest": "deliberate kernel panic (metal test J10)",
    "otaflip": "self-rebooting tryboot proof",
    "rollback-test": "self-rebooting rollback proof",
    "abcommit-metal": "rewrites config.txt/tryboot.txt every boot",
    "rpmb-provision": "irreversible RPMB key write (manufacturing op only)",
    "otp-provision": "irreversible OTP burn (factory only)",
    "txdiag": "GEM TX burst diagnostics",
    "stalldiag": "blocking Wi-Fi TX-stall snapshot",
    "guestprobe": "guest-SSID probe (bench)",
    "rxprof": "RX loop profiler",
    "mipdump": "RP1 MIP register dump",
    "txsram": "superseded TX-through-SRAM experiment",
    "txsweep": "GEM TX size/alignment sweep",
    "sepdiag": "Gate-R metal observability",
    "segmetal": "segmentation arming bench (responder-sim)",
    "dnssink": "DNS sinkhole first-light",
    "dhcp": "smoltcp DHCP first-light",
    "netmetal": "GEM<->smoltcp first-light bridge",
    "stajoin": "WPA2 STA join proof (build-time credentials)",
    "detbench": "detection benchmark corpus replay (QEMU)",
    "wifiheal-bench": "Wi-Fi self-heal metal trigger (injects a synthetic TX freeze / FWHALT)",
    "artstore-bench": "artifact-store metal trigger (tampers the ACTIVE store half on the eMMC, ADR 0059 0.4)",
    "fwcon-fast": "firmware console read every beat + full trap / stack dump (vendor test-firmware diagnostics, REL-08)",
    "t0inv": "ADR 0062 T0 inventory (hboot: ID registers, DTB, mailbox GET tags, gated SMCCC probe — bench only)",
}

LINE = re.compile(r"^([A-Za-z0-9_\-]+) v\S+.*?\|([A-Za-z0-9_,\-]*)\|")


def shipping_features(path=None):
    path = path or os.path.join(ROOT, "tools/ci/shipping-features.txt")
    with open(path) as f:
        feats = "".join(l for l in f if not l.lstrip().startswith("#"))
    feats = re.sub(r"\s+", "", feats)
    if not feats or not re.fullmatch(r"[A-Za-z0-9_\-]+(,[A-Za-z0-9_\-]+)*", feats):
        raise ValueError(f"{path}: not a comma-separated feature list: {feats!r}")
    return feats


def resolve(features):
    cmd = ["cargo", "tree", "-p", "kernel", "--features", features, "-e", "normal,build",
           "--target", "aarch64-unknown-none-softfloat", "--prefix", "none", "--format", "{p} |{f}|"]
    p = subprocess.run(cmd, cwd=os.path.join(ROOT, "os/kernel"), capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"cargo tree failed ({p.returncode}): {p.stderr.strip()[-2000:]}")
    return p.stdout


def active(tree_text):
    """The set of (crate, feature) pairs a `cargo tree --format '{p} |{f}|'` output shows as enabled."""
    out = set()
    for line in tree_text.splitlines():
        m = LINE.match(line.strip())
        if m:
            out.update((m.group(1), f) for f in m.group(2).split(",") if f)
    return out


def violations(pairs):
    return sorted((c, f) for c, f in pairs if f in FORBIDDEN)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tree", help="a saved `cargo tree -e features` output instead of running cargo")
    ap.add_argument("--features", help="check this comma-separated set instead of shipping-features.txt")
    a = ap.parse_args(argv)
    try:
        feats = a.features or shipping_features()
        text = open(a.tree).read() if a.tree else resolve(feats)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"shipping-guard: ERROR {e}")
        return 2
    pairs = active(text)
    if not any(c == "kernel" for c, _ in pairs):
        print("shipping-guard: ERROR the resolved graph shows no kernel features — refusing to call it clean")
        return 2
    bad = violations(pairs)
    for c, f in bad:
        print(f"shipping-guard: FAIL {c} feature \"{f}\" is active in the shipping flavour — {FORBIDDEN[f]}")
    if bad:
        return 1
    kern = sorted(f for c, f in pairs if c == "kernel")
    print(f"shipping-guard: OK {feats} — {len(pairs)} active crate features, none development-only "
          f"(kernel: {', '.join(kern)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
