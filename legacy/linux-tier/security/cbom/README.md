# `security/cbom/` — Cryptographic Bill of Materials

> **ADR 0002 §4 (the CBOM-per-image requirement): "Every build emits a CBOM (CycloneDX
> cryptographic-assets format) alongside the SBOM ... One query answers 'what crypto is
> on this device, and is any of it quantum-vulnerable?'"**

This is the artifact that makes HookProbe's crypto-agility / PQC posture **auditable**,
and it is a differentiator versus appliance vendors that hard-code RSA/ECC
(Readme "Post-quantum readiness").

## The two inputs (and why the CBOM is trustworthy)

```
security/cbom/suites/<suite_id>.yaml   ──┐  (POLICY: which algorithms, per domain)
                                          ├──►  gen-cbom.py  ──►  cbom.cdx.json
image SBOM (syft, CycloneDX)           ──┘  (INVENTORY: which crypto libs ship)
```

1. **Suite (policy).** `suites/hookprobe-pqc-hybrid-2026.yaml` mirrors ADR 0002 §1's
   `crypto` block. The SAME suite is what `hookprobe-bootstrap` embeds into the
   per-device manifest `crypto` block at first boot — so **the CBOM and the on-device
   manifest agree by construction**, not by coincidence. (See the `TODO(shared-source)`
   in the suite file: the suite should ultimately live in one shared location read by
   both bootstrap and this tool.)
2. **SBOM (inventory).** The image SBOM is scanned for crypto-providing libraries
   (openssl, aws-lc, rustls, wasmtime, cosign, ca-certificates). These become
   `related-crypto-material` assets so the CBOM reflects *shipped reality*, not just
   *declared intent*.

## Output

CycloneDX **1.6** JSON, `components[].type == "cryptographic-asset"`:
- one `algorithm` asset per suite algorithm, carrying `nistQuantumSecurityLevel`,
  `cryptoFunctions`, the standard (FIPS 203/204/205, SP 800-208), the **key-custody**
  location (ADR 0002 §5), and flags for `stateful_hbs` / `hybrid_composite`;
- one `related-crypto-material` asset per shipped crypto library;
- a metadata roll-up: `quantum_vulnerable_algorithms` (the "one query" answer) and a
  `hybrid_posture` note explaining that classical legs are quantum-vulnerable *alone* but
  the composite is not.

The CBOM is:
- **COPIED into the image** at `/usr/share/hookprobe/cbom.json` (the path the manifest
  `crypto.cbom` field references — closes the `base/Containerfile` Layer E TODO), and
- **attached as a cosign attestation** on the image (`predicateType
  https://cyclonedx.org/bom`), alongside the SBOM attestation.

## Run it

```bash
pip install -r security/cbom/requirements.txt
python3 security/cbom/gen-cbom.py \
  --suite security/cbom/suites/hookprobe-pqc-hybrid-2026.yaml \
  --image "ghcr.io/hookprobe/os@${IMAGE_DIGEST}" \
  --sbom  sbom.cdx.json \
  --out   cbom.cdx.json
```

## Crypto-agility in practice (ADR 0002)

A swap is: publish a NEW suite file (new `suite_id`) → regenerate the CBOM (this tool) →
re-sign → roll out through fleet rings. **No call site changes** (the provider
abstraction resolves primitives from `suite_id` at runtime). Never mutate an in-use
suite — publish a new named one so old and new hybrid verifiers interoperate during the
transition.

## TODOs only a real build/standards-track can close

- Fill authoritative **OIDs** for ML-DSA-65 / ML-KEM-768 / LMS once finalised.
- Confirm CycloneDX 1.6 `algorithmProperties` enum values against the shipping schema.
- Confirm crypto-library package names against a real syft scan of the trixie image.
- Author the `-fips` sibling suite when a FIPS-validated base (Ubuntu Pro FIPS /
  aws-lc-rs FIPS) is pinned.
