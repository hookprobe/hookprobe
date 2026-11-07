#!/usr/bin/env python3
"""HookProbe OS — CBOM (Cryptographic Bill of Materials) generator.

Implements the ADR 0002 §4 requirement: "Every build emits a CBOM (CycloneDX
cryptographic-assets format) alongside the SBOM ... One query answers 'what crypto is
on this device, and is any of it quantum-vulnerable?'"

The CBOM is generated from TWO inputs (ADR 0002 §1/§4):
  1. the ACTIVE crypto SUITE (security/cbom/suites/<suite_id>.yaml) — the POLICY: which
     algorithms each domain uses. This is the same suite bootstrap embeds into the
     manifest `crypto` block, so the CBOM and the on-device manifest agree by construction.
  2. (optional) the image SBOM (CycloneDX from syft) — the INVENTORY: which crypto-
     PROVIDING libraries are actually present in the image (openssl, libssl, aws-lc,
     wasmtime, cosign, rustls-bearing binaries). These are emitted as `related-crypto-
     material` / library cryptographic-assets so the CBOM reflects shipped reality, not
     just declared policy.

Output: CycloneDX 1.6 JSON with `components[].type == "cryptographic-asset"` and the
`cryptoProperties` block. Attach it to the image as a cosign attestation
(predicateType https://cyclonedx.org/bom) AND COPY it to /usr/share/hookprobe/cbom.json
(the path the manifest `crypto.cbom` field references — see base/Containerfile Layer E TODO).

Usage:
    gen-cbom.py --suite security/cbom/suites/hookprobe-pqc-hybrid-2026.yaml \
                --image ghcr.io/hookprobe/os@sha256:... \
                --sbom sbom.cdx.json \
                --out cbom.cdx.json

HONESTY: runs offline with stdlib + PyYAML. It cannot itself verify that the declared
algorithms match the compiled binaries — that is what the SBOM cross-reference and the
ADR 0002 "no algorithm names at any call site" review gate are for. OIDs are marked
TODO where the authoritative NIST/IANA OID still needs confirming.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("FATAL: PyYAML not installed. Run: pip install -r security/cbom/requirements.txt")

CYCLONEDX_SPEC = "1.6"

# =============================================================================================
# F5 audit fix (2026-07-05): CBOM HONESTY.
# =============================================================================================
# The suite YAML is POLICY (the algorithm set an operator has *chosen*); this map is REALITY
# (what code in THIS repo actually implements today). Before this fix, every algorithm the suite
# named was emitted as a plain cryptographic-asset with no notion of "shipped" vs "aspirational" —
# so the CBOM certified ML-DSA/ML-KEM/LMS post-quantum crypto that zero code implemented. Every
# algorithm component now carries an explicit `hookprobe:status: implemented | roadmap` property
# computed from this map (anything NOT listed here defaults to "roadmap" — fail-closed: an
# unreviewed suite addition must never silently start claiming quantum resistance), and
# `hookprobe:quantum_resistant` is forced `false` for any `roadmap` entry regardless of the
# algorithm's own `pq:` flag — a PQC algorithm nobody has wired up yet protects nothing, so the
# rollup counts it exactly like a classical, quantum-vulnerable one (never resistant-on-paper).
#
# Keep this in lockstep with the code it names — update it in the SAME change that lands (or
# retires) the implementation:
#   - module_signing ML-DSA-65 + Ed25519 (BOTH legs enforced, fail-closed anti-downgrade):
#     crates/hookprobe-manifest/src/module_sig.rs (`verify_module_for_suite`/`sign_module_mldsa`,
#     Part A of the F5 fix).
#   - image_signing: the REAL mechanism is cosign KEYLESS signing (Fulcio-issued short-lived
#     ECDSA-P256 cert, Rekor transparency log) — see `.github/workflows/build-os.yml`'s
#     `cosign sign --yes`. NOT ml-dsa: the suite's OLD image_signing entry (ml-dsa-65 + ed25519)
#     never matched what the pipeline does, so this fix replaces the domain's algorithm set
#     itself (see the suite YAML), not just its status tag.
#   - device_identity Ed25519: crates/hookprobe-manifest/src/identity.rs — a software-PUF
#     (deterministic Ed25519 re-derived from hardware fingerprints each boot; Part D of the F5
#     fix). The suite's ML-DSA-65 leg for this domain is NOT implemented there — roadmap.
#   - hash SHA-256/SHA-384/SHA3-256: crates/hookprobe-manifest/src/module_sig.rs::digest_hex.
#   - data_at_rest AES-256-GCM: security/crypt/*.sh + base/scripts/*.sh (LUKS2 + Clevis/TPM
#     sealing of the persistent data partition).
#   - boot_signing LMS, tls_kex ML-KEM-768+X25519, tls_auth ML-DSA-65/ECDSA-P256: NO CODE in this
#     tree implements any of these today — SP 800-208 stateful hash-based-signature state
#     management and a TLS/rustls stack are both unbuilt. Roadmap, not fabricated.
IMPLEMENTED_ALGOS = {
    ("module_signing", "ml-dsa-65"),
    ("module_signing", "ed25519"),
    ("image_signing", "ecdsa-p256"),
    ("device_identity", "ed25519"),
    ("data_at_rest", "aes-256-gcm"),
    ("hash", "sha-256"),
    ("hash", "sha-384"),
    ("hash", "sha3-256"),
}

# Crypto-providing libraries we recognise in an SBOM, by (regex on package name) ->
# (human label, what it provides). Best-effort; extend as the image grows.
# TODO: confirm package names against a REAL syft run of the built image (Debian trixie
#       package names differ from upstream project names).
CRYPTO_LIBRARY_PATTERNS = [
    (re.compile(r"^libssl|^openssl"),        "OpenSSL",       "system TLS / X.509 / digest baseline"),
    (re.compile(r"^libcrypto"),              "OpenSSL libcrypto", "system crypto primitives"),
    (re.compile(r"aws-lc|aws_lc"),           "aws-lc-rs",     "rustls crypto provider (FIPS-capable)"),
    (re.compile(r"^rustls"),                 "rustls",        "TLS stack (hybrid ML-KEM KEX)"),
    (re.compile(r"ml-kem|ml_kem"),           "RustCrypto ml-kem", "FIPS 203 KEM"),
    (re.compile(r"ml-dsa|ml_dsa"),           "RustCrypto ml-dsa", "FIPS 204 signatures"),
    (re.compile(r"^cosign"),                 "cosign",        "image/module signature verification (on-device)"),
    (re.compile(r"^wasmtime"),               "wasmtime",      "Wasm runtime (module sandbox)"),
    (re.compile(r"libgcrypt|gnutls"),        "GnuTLS/libgcrypt", "system crypto (transitive)"),
    (re.compile(r"^ca-certificates"),        "ca-certificates", "system trust store"),
]


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _primitive_to_cdx(primitive: str) -> str:
    """Map our suite `primitive` to CycloneDX algorithmProperties.primitive enum."""
    # CycloneDX 1.6 primitive enum: drbg, mac, blockcipher, streamcipher, signature,
    # hash, pke, ae, combiner, kem, kdf, key-agree, other, unknown.
    return {
        "signature": "signature",
        "kem": "kem",
        "ae": "ae",
        "hash": "hash",
        "kdf": "kdf",
        "mac": "mac",
    }.get(primitive, "other")


def algorithm_component(domain: str, algo: dict) -> dict:
    """One suite algorithm -> one CycloneDX cryptographic-asset (assetType=algorithm).

    HONESTY (F5 fix): `hookprobe:status` says whether code in this repo actually implements this
    algorithm TODAY (`IMPLEMENTED_ALGOS`) vs merely names it as chosen policy (`roadmap`).
    `hookprobe:quantum_resistant` is the claim that actually matters for the rollup below: it is
    forced `false` for a `roadmap` entry even when the algorithm's own `pq:` flag is `true` — an
    unimplemented PQC leg protects nothing, so it must count as quantum-vulnerable, not resistant.
    """
    name = algo["name"]
    ref = f"crypto/algorithm/{domain}/{name.lower().replace('+', '-plus-')}"
    status = "implemented" if (domain, name.lower()) in IMPLEMENTED_ALGOS else "roadmap"
    quantum_resistant = bool(algo.get("pq", False)) and status == "implemented"
    props = {
        "primitive": _primitive_to_cdx(algo.get("primitive", "other")),
        "cryptoFunctions": algo.get("function", []),
        # NIST PQC category is an intrinsic property of the algorithm itself (unaffected by
        # whether THIS repo has implemented it yet) — the honesty gate is `quantum_resistant`
        # below, not this field.
        "nistQuantumSecurityLevel": algo.get("nist_level", 0),
    }
    if "classical_bits" in algo:
        props["classicalSecurityLevel"] = algo["classical_bits"]
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": props,
            # oid: TODO — fill authoritative NIST/IANA OIDs (e.g. ML-DSA-65, ML-KEM-768)
            #      once finalised; absence is valid CycloneDX.
        },
        "properties": [
            {"name": "hookprobe:domain", "value": domain},
            {"name": "hookprobe:standard", "value": algo.get("standard", "")},
            {"name": "hookprobe:status", "value": status},
            {"name": "hookprobe:quantum_resistant", "value": str(quantum_resistant).lower()},
            {"name": "hookprobe:key_custody", "value": ""},  # filled by caller per-domain
        ],
    }
    if status == "roadmap":
        comp["properties"].append({
            "name": "hookprobe:roadmap_note",
            "value": "named in policy; NOT YET IMPLEMENTED in this repo — counted quantum-vulnerable "
                     "until it ships (see security/cbom/gen-cbom.py IMPLEMENTED_ALGOS)",
        })
    if algo.get("stateful"):
        comp["properties"].append({"name": "hookprobe:stateful_hbs", "value": "true"})
        comp["properties"].append(
            {"name": "hookprobe:state_management",
             "value": "release-HSM-only (SP 800-208); leaf index never forked — see security/cosign/KEY-CUSTODY.md"}
        )
    if algo.get("hybrid"):
        comp["properties"].append({"name": "hookprobe:hybrid_composite", "value": "true"})
    return comp


def library_components_from_sbom(sbom_path: Path) -> list[dict]:
    """Extract crypto-providing libraries from a CycloneDX SBOM as related-crypto-material."""
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"  warn: could not read SBOM {sbom_path}: {e} (skipping library inventory)", file=sys.stderr)
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for comp in sbom.get("components", []):
        nm = (comp.get("name") or "").lower()
        for pat, label, role in CRYPTO_LIBRARY_PATTERNS:
            if pat.search(nm) and label not in seen:
                seen.add(label)
                out.append({
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto/library/{label.lower().replace(' ', '-').replace('/', '-')}",
                    "name": label,
                    "version": comp.get("version", "unknown"),
                    "cryptoProperties": {
                        "assetType": "related-crypto-material",
                        "relatedCryptoMaterialProperties": {"type": "additional"},
                    },
                    "properties": [
                        {"name": "hookprobe:role", "value": role},
                        {"name": "hookprobe:sbom_purl", "value": comp.get("purl", "")},
                    ],
                })
                break
    return out


def build_cbom(suite: dict, image_ref: str, sbom_path: Path | None) -> dict:
    suite_id = suite["suite_id"]
    components: list[dict] = []
    for domain, body in suite.get("domains", {}).items():
        custody = body.get("key_custody", "unspecified")
        for algo in body.get("algorithms", []):
            comp = algorithm_component(domain, algo)
            for p in comp["properties"]:
                if p["name"] == "hookprobe:key_custody":
                    p["value"] = custody
            components.append(comp)

    if sbom_path:
        components.extend(library_components_from_sbom(sbom_path))

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "component": {
                "type": "operating-system",
                "bom-ref": image_ref,
                "name": "hookprobe-os",
                # image digest is the subject the cosign attestation binds to.
                "purl": f"pkg:oci/hookprobe-os?repository_url={image_ref}",
            },
            "properties": [
                {"name": "hookprobe:crypto_suite_id", "value": suite_id},
                {"name": "hookprobe:cbom_generator", "value": "security/cbom/gen-cbom.py"},
                {"name": "hookprobe:adr", "value": "ADR-0002"},
            ],
            "tools": {"components": [
                {"type": "application", "name": "hookprobe-gen-cbom", "version": "0.1.0"}
            ]},
        },
        "components": components,
    }

    # Roll up a quantum-vulnerability summary (the ADR 0002 §4 "one query" answer). HONESTY (F5
    # fix): `hookprobe:quantum_resistant` is already forced `false` for any `roadmap` algorithm
    # (see `algorithm_component`), so a domain whose PQC leg is merely policy-named — not
    # implemented — falls straight into THIS vulnerable list, exactly like a plain classical
    # algorithm. No domain is quantum-resistant "on paper" here.
    # Domain-QUALIFIED, not just by algorithm name: the SAME algorithm name (e.g. "ML-DSA-65") can
    # be `implemented` in one domain (module_signing) and `roadmap` in another (device_identity,
    # tls_auth) — a naive name-only rollup would smear the roadmap instances' vulnerability onto
    # the implemented one (or vice versa). `domain/name` keeps each domain's verdict distinct.
    algo_components = [c for c in components if c["cryptoProperties"]["assetType"] == "algorithm"]
    vulnerable = [
        f"{next(p['value'] for p in c['properties'] if p['name'] == 'hookprobe:domain')}/{c['name']}"
        for c in algo_components
        if not any(p["name"] == "hookprobe:quantum_resistant" and p["value"] == "true"
                    for p in c.get("properties", []))
    ]
    bom["metadata"]["properties"].append(
        {"name": "hookprobe:quantum_vulnerable_algorithms",
         "value": ",".join(sorted(set(vulnerable))) or "none"}
    )

    # Per-domain verdict: "implemented" (every named algorithm in the domain ships today),
    # "roadmap" (none do), or "partial" (a mix — e.g. device_identity today: Ed25519 implemented,
    # its ML-DSA-65 leg roadmap). Computed from the SAME per-algorithm status just assigned above
    # — never hand-maintained prose that can drift from what `IMPLEMENTED_ALGOS` actually says.
    domain_algo_status: dict[str, set[str]] = {}
    for c in algo_components:
        dom = next(p["value"] for p in c["properties"] if p["name"] == "hookprobe:domain")
        st = next(p["value"] for p in c["properties"] if p["name"] == "hookprobe:status")
        domain_algo_status.setdefault(dom, set()).add(st)
    domain_summary = []
    for dom in sorted(domain_algo_status):
        statuses = domain_algo_status[dom]
        verdict = "implemented" if statuses == {"implemented"} else ("roadmap" if statuses == {"roadmap"} else "partial")
        domain_summary.append(f"{dom}={verdict}")
    bom["metadata"]["properties"].append(
        {"name": "hookprobe:domain_status", "value": ",".join(domain_summary)}
    )

    # Hybrid/composite posture — HONEST version: a domain only gets real "break both legs" PQC+
    # classical protection when it has an IMPLEMENTED `pq:true` algorithm AND an IMPLEMENTED
    # `pq:false` algorithm (a genuine composite pairing — this deliberately excludes e.g. `hash`,
    # which has multiple implemented algorithms but no classical/PQC pairing to speak of, so it
    # is not "hybrid" in the composite-signature sense this property means to convey). Computed,
    # not asserted — a domain drops out the moment one of its legs stops shipping.
    hybrid_domains = []
    for dom in sorted(domain_algo_status):
        implemented_in_domain = [
            c for c in algo_components
            if any(p["name"] == "hookprobe:domain" and p["value"] == dom for p in c["properties"])
            and any(p["name"] == "hookprobe:status" and p["value"] == "implemented" for p in c["properties"])
        ]
        has_pq = any(c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] > 0 for c in implemented_in_domain)
        has_classical = any(c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0 for c in implemented_in_domain)
        if has_pq and has_classical:
            hybrid_domains.append(dom)
    bom["metadata"]["properties"].append(
        {"name": "hookprobe:hybrid_posture",
         "value": (
             f"domain(s) with >=2 IMPLEMENTED legs today (composite — an attacker must break "
             f"BOTH): {','.join(hybrid_domains) or 'none'}. A domain's roadmap-status leg (see "
             f"hookprobe:status per component) contributes NO composite protection yet — it is "
             f"counted in hookprobe:quantum_vulnerable_algorithms, not here."
         )}
    )
    return bom


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate a CycloneDX CBOM from the active crypto suite + image SBOM.")
    ap.add_argument("--suite", required=True, type=Path, help="path to security/cbom/suites/<id>.yaml")
    ap.add_argument("--image", required=True, help="image ref (ideally @sha256: digest) — CBOM subject")
    ap.add_argument("--sbom", type=Path, default=None, help="optional CycloneDX SBOM (syft) for the library inventory")
    ap.add_argument("--out", required=True, type=Path, help="output CBOM path (.cdx.json)")
    args = ap.parse_args(argv[1:])

    suite = yaml.safe_load(args.suite.read_text(encoding="utf-8"))
    if "suite_id" not in suite or "domains" not in suite:
        sys.exit(f"FATAL: {args.suite} is not a valid crypto suite (need suite_id + domains).")

    bom = build_cbom(suite, args.image, args.sbom)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")

    algos = sum(1 for c in bom["components"] if c["cryptoProperties"]["assetType"] == "algorithm")
    libs = sum(1 for c in bom["components"] if c["cryptoProperties"]["assetType"] == "related-crypto-material")
    qv = next(p["value"] for p in bom["metadata"]["properties"] if p["name"] == "hookprobe:quantum_vulnerable_algorithms")
    print(f"CBOM written: {args.out}")
    print(f"  suite_id={suite['suite_id']}  algorithms={algos}  libraries={libs}")
    print(f"  quantum-vulnerable (standalone): {qv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
