# `security/sbom/` — Software Bill of Materials

> **ADR 0002 §4 / Readme "Security & supply chain": SBOM per image, SBOM per module.**
> Ship a Software Bill of Materials so operators and regulators can inventory every
> dependency in one query (SOC 2 / ISO 27001 / EU CRA evidence).

## What is produced

| Artifact | Source | Tool | Format | Where it goes |
|---|---|---|---|---|
| **Image SBOM** | the built bootc OCI image (all layers) | `syft` | CycloneDX JSON (+ SPDX JSON) | cosign attestation on the image (`--type cyclonedx`) + CI artifact |
| **Module SBOM** | each Wasm/sysext module source + built artifact | `cargo cyclonedx` (crates) / `syft` (artifact) | CycloneDX JSON | cosign attestation on the module OCI artifact + CI artifact |

The **CycloneDX** SBOM is canonical for HookProbe because `security/cbom/gen-cbom.py`
cross-references it to build the **library inventory** half of the CBOM (the crypto
libraries actually shipped: openssl, aws-lc, wasmtime, cosign, rustls). SPDX is emitted
in parallel only for broad tooling compatibility.

## How (CI)

```bash
# Image (build-os.yml):
syft -c security/sbom/syft.yaml \
     "ghcr.io/hookprobe/os@${IMAGE_DIGEST}" \
     -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json

# Module crates (build-modules.yml) — accurate Rust dependency tree:
cargo cyclonedx --format json --target wasm32-wasip1   # emits per-crate <name>.cdx.json
```

## Reproducibility

The Readme threat model lists **reproducible builds** as the supply-chain control. For
the SBOM to be stable across `syft` upgrades the `default-catalogers` set must be pinned
(TODO in `syft.yaml`) and the Rust binaries should be built with `cargo auditable` so
syft's binary cataloger recovers their full crate inventory (TODO: enable in the
workspace build — out of scope for this directory; flagged for `code-developer`).

## TODOs only a real build can close

- Confirm Debian **trixie** package names (`libssl3` etc.) so the CBOM library patterns
  in `security/cbom/gen-cbom.py` actually match.
- Pin syft `default-catalogers` for deterministic SBOMs.
- Decide whether the host-integral Rust binaries are SBOM'd in-image (current
  Containerfile build stage) or as independently-attested artifacts injected at build
  (the alternative path noted in `base/Containerfile` Stage 1 TODO).
