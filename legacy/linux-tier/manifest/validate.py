#!/usr/bin/env python3
"""HookProbe OS Platform Manifest validation harness.

Validates every manifest in manifest/examples/ against the canonical JSON Schema
(manifest/schema/manifest.schema.json) AND runs the semantic invariants from
ADR 0003 that JSON Schema cannot express. Exits non-zero if any check fails so it
can gate CI.

Usage:
    python3 manifest/validate.py            # validate examples/
    python3 manifest/validate.py path.json  # validate specific file(s)

Requires: jsonschema  (pip install jsonschema)
"""
from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("FATAL: jsonschema not installed. Run: pip install jsonschema")

try:
    import yaml  # PyYAML — for the platforms/*.yaml cross-check
except ImportError:
    yaml = None

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SCHEMA_PATH = HERE / "schema" / "manifest.schema.json"
EXAMPLES_GLOB = str(HERE / "examples" / "*.manifest.json")
PLATFORMS_DIR = REPO / "platforms"

# Module states that still consume their resource budget (vs terminal states).
LIVE_MODULE_STATES = {"pending", "running", "throttled", "paused"}


def load_json(path: Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --- Semantic invariants (ADR 0003 §"Validation invariants") -----------------

def check_allocatable(m) -> list[str]:
    """#4: resources.allocatable == total - reserved, per dimension; all >= 0."""
    errs = []
    r = m["resources"]
    for dim in ("cpu_pct", "memory_mb"):
        expected = r["total"][dim] - r["reserved"][dim]
        if r["allocatable"][dim] != expected:
            errs.append(
                f"resources.allocatable.{dim}={r['allocatable'][dim]} "
                f"!= total-reserved={expected}"
            )
        if r["allocatable"][dim] < 0:
            errs.append(f"resources.allocatable.{dim} is negative")
    return errs


def check_version_consistency(m) -> list[str]:
    if m["schema_version"] != m["provenance"]["schema_version"]:
        return ["schema_version != provenance.schema_version"]
    return []


def check_module_budgets_fit(m) -> list[str]:
    """Sum of live module budgets must fit within resources.allocatable."""
    errs = []
    alloc = m["resources"]["allocatable"]
    for dim in ("cpu_pct", "memory_mb"):
        used = sum(
            mod["budget"][dim]
            for mod in m["modules"]
            if mod["state"] in LIVE_MODULE_STATES
        )
        if used > alloc[dim]:
            errs.append(
                f"live module {dim} budgets sum to {used} > allocatable {alloc[dim]}"
            )
    return errs


def check_signature_structure(m) -> list[str]:
    """#7 (structural only — full cosign verification runs in release CI)."""
    errs = []
    sig = m["signature"]
    if sig["tpm_sealed"] and not sig["pcr_policy"]:
        errs.append("signature.tpm_sealed is true but pcr_policy is null")
    if not sig["tpm_sealed"] and sig["pcr_policy"] is not None:
        errs.append("signature.tpm_sealed is false but pcr_policy is set")
    return errs


def check_generic_baseline(m) -> list[str]:
    """#2: a 'generic' class grants ONLY the software SOC baseline — never a
    hardware- or data-path-gated capability. The software baseline (soc, ids +
    host_telemetry/dns_filtering/threat_intel) needs nothing but the CPU and the
    image's own kernel, so an unrecognized box still runs a full local SOC; anything
    hardware/datapath-bound (capture/openvswitch/wifi_ap/edge_ai/inline_ips/…) must
    stay withheld until a real profile validates the silicon."""
    if m["platform"]["class"] != "generic":
        return []
    baseline = {"soc", "ids", "host_telemetry", "dns_filtering", "threat_intel"}
    granted = {t for t, c in m["capabilities"].items() if c["state"] == "granted"}
    extra = granted - baseline
    if extra:
        return [f"generic class granted non-baseline (hardware/datapath) capabilities: {sorted(extra)}"]
    return []


def _load_platforms() -> dict | None:
    """Map profile -> platform spec from platforms/*.yaml (None if PyYAML absent)."""
    if yaml is None or not PLATFORMS_DIR.is_dir():
        return None
    out = {}
    for p in sorted(PLATFORMS_DIR.glob("*.yaml")):
        spec = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if "profile" in spec:
            out[spec["profile"]] = spec
    return out


_PLATFORMS = _load_platforms()


def check_platform_profile(m) -> list[str]:
    """Every example's platform.profile must have a matching platforms/<p>.yaml
    whose class agrees (keeps the manifest output and platform input consistent)."""
    if _PLATFORMS is None:
        return []  # PyYAML/platforms unavailable — skip silently
    prof = m["platform"]["profile"]
    spec = _PLATFORMS.get(prof)
    if spec is None:
        return [f"platform.profile '{prof}' has no platforms/{prof}.yaml"]
    if spec.get("class") != m["platform"]["class"]:
        return [f"platform.class '{m['platform']['class']}' != platforms/{prof}.yaml class '{spec.get('class')}'"]
    return []


SEMANTIC_CHECKS = [
    check_allocatable,
    check_version_consistency,
    check_module_budgets_fit,
    check_signature_structure,
    check_generic_baseline,
    check_platform_profile,
]


# --- Runner ------------------------------------------------------------------

def validate_file(path: Path, validator: Draft202012Validator) -> list[str]:
    errs: list[str] = []
    try:
        m = load_json(path)
    except json.JSONDecodeError as e:
        return [f"invalid JSON: {e}"]

    for e in sorted(validator.iter_errors(m), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in e.path) or "<root>"
        errs.append(f"schema: {loc}: {e.message}")

    # Only run semantic checks if the document is structurally sound enough.
    if not errs:
        for check in SEMANTIC_CHECKS:
            errs.extend(f"invariant: {msg}" for msg in check(m))
    return errs


def main(argv: list[str]) -> int:
    schema = load_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)  # the schema itself is valid
    validator = Draft202012Validator(schema)

    targets = [Path(a) for a in argv[1:]] or [Path(p) for p in sorted(glob.glob(EXAMPLES_GLOB))]
    if not targets:
        print("No manifests found to validate.")
        return 1

    print(f"Schema OK: {SCHEMA_PATH.relative_to(HERE.parent)}")
    print(f"Validating {len(targets)} manifest(s)\n")

    failures = 0
    for path in targets:
        errs = validate_file(path, validator)
        name = path.name
        if errs:
            failures += 1
            print(f"  FAIL  {name}")
            for e in errs:
                print(f"          - {e}")
        else:
            print(f"  PASS  {name}")

    print()
    if failures:
        print(f"RESULT: {failures}/{len(targets)} manifest(s) failed.")
        return 1
    print(f"RESULT: all {len(targets)} manifest(s) valid.")
    print("NOTE: full cosign signature verification and probert round-trip (ADR 0003 #7/#8) run in release CI, not here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
