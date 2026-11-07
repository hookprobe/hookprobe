#!/usr/bin/env python3
"""HookProbe OS — Platform Manifest generator (REFERENCE implementation).

Pipeline (Architecture.md C4-C7): raw scan facts -> classify -> map capabilities
(grant = presence AND known-good AND policy) -> allocate resources -> assemble +
sign -> manifest.json (schema 2, ADR 0003).

This is the executable REFERENCE that nails the logic and is testable offline via
manifest/fixtures/. The SHIPPING bootstrap is Rust (aligns with ADR 0001 / OS
supply-chain posture) and additionally performs REAL cosign signing + TPM sealing,
which this reference stubs (it emits an UNSIGNED reference manifest).

Usage:
    python3 bootstrap/reference/generate_manifest.py manifest/fixtures/rk3588.profile.json
    python3 bootstrap/reference/generate_manifest.py FIXTURE -o out.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("FATAL: PyYAML not installed. Run: pip install -r manifest/requirements.txt")

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PLATFORMS_DIR = REPO / "platforms"
STORAGE_OVERHEAD = 0.8  # fraction of raw storage usable for the data partition

# Crypto suites (ADR 0002). In the shipping build these live in security/ and the
# active set is resolved per device; here we ship the one named suite.
#
# HONESTY (F5 audit fix, 2026-07-05): mirrors crates/hookprobe-manifest/src/crypto.rs exactly —
# `image_signing` is `["ml-dsa-65", ...]` no longer; the REAL mechanism is cosign KEYLESS signing
# (Fulcio-issued ECDSA-P256 cert, `.github/workflows/build-os.yml`), so the on-device manifest
# must self-report that, not an aspirational PQC algorithm nothing implements. See
# `security/cbom/suites/hookprobe-pqc-hybrid-2026.yaml` for the full implemented/roadmap ledger.
CRYPTO_SUITES = {
    "hookprobe-pqc-hybrid-2026": {
        "agility": True,
        "suite_id": "hookprobe-pqc-hybrid-2026",
        "image_signing": ["ecdsa-p256"],
        "module_signing": ["ml-dsa-65", "ed25519"],
        "boot_signing": "lms",
        "tls_kex": ["ml-kem-768+x25519"],
        "tls_auth": ["ml-dsa-65", "ecdsa-p256"],
        "data_at_rest": "aes-256-gcm",
        "hash": ["sha-256", "sha-384", "sha3-256"],
        "device_identity": ["ml-dsa-65", "ed25519"],
        "cbom": "/usr/share/hookprobe/cbom.json",
    }
}

BLANK_DMI = {"", "default string", "to be filled by o.e.m.", "system manufacturer", "system product name"}


# --- helpers -----------------------------------------------------------------

def _sha256_tag(obj) -> str:
    return "SHA256:" + hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def _dmi_field(dmi, key) -> str | None:
    if not dmi:
        return None
    v = (dmi.get(key) or "").strip()
    return None if v.lower() in BLANK_DMI else v


def load_platforms() -> list[dict]:
    out = []
    for p in sorted(PLATFORMS_DIR.glob("*.yaml")):
        spec = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if "profile" in spec:
            out.append(spec)
    return out


# --- stage 1: classify (priority tree, Architecture.md C5) -------------------

def classify(scan, platforms) -> tuple[dict, dict]:
    """Return (platform_spec, match) using device-tree -> dmi-tuple -> fallback."""
    by_method = lambda meth: [p for p in platforms if p.get("match", {}).get("method") == meth]

    # 1) device-tree (ARM)
    dt = scan.get("device_tree_compatible") or []
    for spec in by_method("device-tree"):
        for token in spec["match"].get("device_tree_compatible", []):
            if token in dt:
                return spec, {"method": "device-tree", "key": token}

    # 2) DMI tuple (x86)
    vendor = _dmi_field(scan.get("dmi"), "sys_vendor")
    product = _dmi_field(scan.get("dmi"), "product_name")
    board = _dmi_field(scan.get("dmi"), "board_name")
    if vendor or product or board:
        import fnmatch
        for spec in by_method("dmi-tuple"):
            for tup in spec["match"].get("dmi_tuples", []):
                if (fnmatch.fnmatch(vendor or "", tup.get("sys_vendor", "*"))
                        and fnmatch.fnmatch(product or "", tup.get("product_name", "*"))
                        and fnmatch.fnmatch(board or "", tup.get("board_name", "*"))):
                    return spec, {"method": "dmi-tuple", "key": f"{vendor};{product};{board}"}

    # 3) fallback (generic)
    for spec in by_method("fallback"):
        return spec, {"method": "fallback", "key": "unknown"}
    raise SystemExit("No fallback profile found in platforms/ (generic.yaml missing).")


# --- stage 2: capability mapper (grant = presence AND known-good AND policy) --

# npu.driver_ready is scan-dependent (see _absent_reason) and deliberately NOT here:
# "no NPU present" and "NPU present but driver not loaded" are two different honest facts.
FRIENDLY_ABSENT = {
    "wifi.present": "no Wi-Fi radio present",
    "network.role:inline": "no interface assigned an inline role",
}


def _eval_requirement(expr, scan, granted, cap_tokens=frozenset()) -> bool:
    if expr in cap_tokens:                            # capability dependency (any token)
        return granted.get(expr) == "granted"
    if expr in ("cpu", "memory_mb", "arch"):         # presence of a base fact
        return scan.get(expr) is not None
    if ">=" in expr:
        left, num = expr.split(">=")
        num = int(num)
        if left == "memory_mb":
            return scan.get("memory_mb", 0) >= num
        if left == "network.interfaces":
            return len(scan.get("interfaces", [])) >= num
    if expr == "wifi.present":
        return bool(scan.get("wifi", {}).get("present"))
    if expr == "npu.driver_ready":
        return bool(scan.get("npu", {}).get("driver_ready"))
    if expr == "network.role:inline":
        return any(i.get("role") == "inline" for i in scan.get("interfaces", []))
    return False


def _inline_iface(scan):
    return next((i for i in scan.get("interfaces", []) if i.get("role") == "inline"), None)


def map_capabilities(scan, platform):
    caps = {}
    granted = {}
    cap_tokens = frozenset(platform.get("capabilities", {}).keys())
    # YAML lists tokens deps-first, so a single pass resolves capability deps.
    for token, pol in platform.get("capabilities", {}).items():
        requires = pol.get("requires", [])
        policy_on = pol.get("policy", "enabled") == "enabled"
        failed = [r for r in requires if not _eval_requirement(r, scan, granted, cap_tokens)]

        # known-good check (currently NIC-driver gating for inline_ips)
        known_good = True
        kg_reason = None
        if token == "inline_ips" and not failed:
            iface = _inline_iface(scan)
            kg_list = pol.get("known_good_nic_drivers", [])
            drv = (iface or {}).get("driver")
            if drv not in kg_list:
                known_good = False
                kg_reason = f"NIC offload (TSO/LRO) not on known-good list for driver '{drv}'"

        # resolve state: absent -> present_unsafe -> policy_denied -> granted
        if failed:
            state = "absent"
            reason = FRIENDLY_ABSENT.get(failed[0]) or _absent_reason(failed[0], scan)
            evidence = [_neg_evidence(failed[0], scan)]
        elif not known_good:
            state, reason = "present_unsafe", kg_reason
            evidence = [f"network.role:inline:{(_inline_iface(scan) or {}).get('name')}"]
        elif not policy_on:
            state = "policy_denied"
            reason = f"withheld on '{platform['class']}' platform class by policy"
            evidence = requires
        else:
            state, reason = "granted", None
            evidence = list(requires)
            if token == "inline_ips":
                evidence.append(f"nic:{(_inline_iface(scan) or {}).get('driver')} known-good")

        caps[token] = {"state": state, "reason": reason, "evidence": evidence}
        granted[token] = state
    return caps


def _absent_reason(expr, scan) -> str:
    if expr == "network.interfaces>=2":
        return f"requires >=2 network interfaces; {len(scan.get('interfaces', []))} present"
    if expr == "memory_mb>=8192":
        return f"requires >=8192 MB; {scan.get('memory_mb')} present"
    if expr == "npu.driver_ready":
        # Honest: distinguish "no accelerator silicon" from "silicon present, driver not loaded"
        # (edge_ai runtime unreachable) — never fabricate "no NPU" on a board that HAS one.
        if scan.get("npu", {}).get("present"):
            return "NPU present but its driver is not loaded — edge_ai runtime unreachable; vendor the accelerator driver in the image"
        return "no NPU/accelerator present"
    return f"requires not met: {expr}"


def _neg_evidence(expr, scan) -> str:
    if expr == "network.interfaces>=2":
        return f"network.interfaces=={len(scan.get('interfaces', []))}"
    if expr == "wifi.present":
        return "wifi.present=false"
    if expr == "npu.driver_ready":
        return "npu.present=false" if not scan.get("npu", {}).get("present") else "npu.driver_ready=false"
    if expr == "network.role:inline":
        return "network.interfaces:no-inline"
    return expr


# --- stage 3: resources + retention ------------------------------------------

def allocate_resources(scan, platform):
    total = {"cpu_pct": scan["cpu"]["cores"] * 100, "memory_mb": scan["memory_mb"]}
    reserved = platform["resources"]["reserved"]
    allocatable = {k: total[k] - reserved[k] for k in total}
    return {"total": total, "reserved": dict(reserved), "allocatable": allocatable,
            "defaults": platform["resources"]["defaults"]}


def compute_retention(scan, platform, now_iso):
    usable = sum(s.get("size_gb", 0) for s in scan.get("storage", [])) * STORAGE_OVERHEAD
    tiers = []
    for name, frac in platform.get("retention", {}).get("tier_fractions", {}).items():
        cap = round(usable * frac)
        tiers.append({"name": name, "cap_gb": cap, "window": _window_bucket(name, cap)})
    return {"tiers": tiers, "computed_at": now_iso}


def _window_bucket(name, cap_gb) -> str:
    # Coarse, honest default — real window depends on traffic volume.
    if name == "pcap":
        return "hours" if cap_gb < 16 else "~1 day"
    if name == "events":
        return "~1-2 weeks" if cap_gb < 24 else "~1-2 months"
    return "months" if cap_gb < 24 else "year+"


# --- stage 4: assemble + (stub) sign -----------------------------------------

def build_manifest(scan, platform, match, now_iso, image_ref, image_digest):
    fingerprint = _sha256_tag({
        "arch": scan["arch"], "cpu": scan["cpu"], "memory_mb": scan["memory_mb"],
        "match": match, "storage": [s["dev"] for s in scan.get("storage", [])],
    })
    has_tpm = bool(scan.get("tpm", {}).get("present"))

    return {
        "schema_version": 2,
        "identity": {
            "device_id": "hp-" + fingerprint.split(":")[1][:32],
            "serial": _dmi_field(scan.get("dmi"), "product_name") and None or None,  # real serial probe in shipping impl
            "idevid": {
                "type": "tpm" if has_tpm else "software",
                "pubkey_fpr": _sha256_tag({"id": fingerprint, "kind": "idevid"}),
                "sealed": has_tpm,
            },
            "claim_state": "unclaimed",
            "tenant": None,
        },
        "platform": {
            "class": platform["class"],
            "profile": platform["profile"],
            "sku": platform.get("sku"),
            "match": match,
        },
        "hardware": {
            "arch": scan["arch"], "cpu": scan["cpu"], "memory_mb": scan["memory_mb"],
            "storage": scan["storage"], "tpm": scan["tpm"], "secure_boot": scan["secure_boot"],
            "npu": scan["npu"], "virt": scan["virt"], "fingerprint": fingerprint,
        },
        "network": {
            "interfaces": [
                {"name": i["name"], "mac": i.get("mac"), "type": i["type"],
                 "supported_modes": i.get("supported_modes", []),
                 "role": i.get("role", "unassigned"),
                 "fail_mode": (i.get("fail_mode", "fail-open") if i.get("role") == "inline" else None),
                 "state": i.get("state", "unknown")}
                for i in scan.get("interfaces", [])
            ],
            "wifi": scan.get("wifi", {"present": False}),
            "lte": scan.get("lte", {"present": False}),
        },
        "capabilities": map_capabilities(scan, platform),
        "resources": allocate_resources(scan, platform),
        "crypto": CRYPTO_SUITES[platform["crypto_suite"]],
        "retention": compute_retention(scan, platform, now_iso),
        "modules": [],
        "provenance": {
            "image_ref": image_ref, "image_digest": image_digest,
            "generated_at": now_iso, "generator": "bootstrap-ref/0.1.0", "schema_version": 2,
        },
        # STUB signature — the shipping (Rust) bootstrap performs real cosign signing
        # + TPM sealing here. This reference emits an explicitly UNSIGNED manifest.
        "signature": {
            "method": "cosign",
            "sig": "UNSIGNED-REFERENCE-BUILD",
            "cert": "UNSIGNED-REFERENCE-BUILD",
            "tpm_sealed": False,
            "pcr_policy": None,
        },
    }


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="HookProbe Platform Manifest reference generator")
    ap.add_argument("fixture", help="probert-style scan profile JSON")
    ap.add_argument("-o", "--out", help="output path (default: stdout)")
    ap.add_argument("--now", help="override generated_at (ISO-8601); default: now")
    ap.add_argument("--image-ref", default="ghcr.io/hookprobe/os:dev")
    ap.add_argument("--image-digest", default="sha256:" + "0" * 64)
    args = ap.parse_args(argv[1:])

    scan = json.loads(Path(args.fixture).read_text(encoding="utf-8"))["scan"]
    now_iso = args.now or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    platform, match = classify(scan, load_platforms())
    manifest = build_manifest(scan, platform, match, now_iso, args.image_ref, args.image_digest)

    out = json.dumps(manifest, indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
        print(f"wrote {args.out}  (class={platform['class']}, profile={platform['profile']}, "
              f"match={match['method']}:{match['key']})", file=sys.stderr)
        print("WARNING: UNSIGNED reference manifest — real cosign+TPM sealing happens in the Rust bootstrap.",
              file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
