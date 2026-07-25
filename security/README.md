# `security/` — supply chain, signing & crypto policy

> **"Trust nothing unsigned." (Readme Principle 7 / ADR 0002.)** HookProbe OS is itself a
> high-value security target, so the integrity of the *whole stack* — image, modules,
> manifest, boot chain — is the credibility moat. This directory holds the tooling and
> policy that make every artifact **signed, inventoried (SBOM + CBOM), and provenanced**,
> and that keep crypto **agile / PQC-ready** per ADR 0002.

## ⚠️ Honest scope

This is the **reviewed supply-chain tooling + policy**. The generators here run offline
(the CBOM generator is exercised in `build-os.yml`); the **signing, attesting, and
boot-verifying steps cannot run on the dev box** (no registry, no cosign identity, no
HSM, no privileged builder). They run when the repo is pushed to GitHub with secrets.
Genuine unknowns are marked `# TODO`. The companion definitions are in
`.github/workflows/build-os.yml` and `.github/workflows/build-modules.yml`.

## Layout

| Path | What | Canon |
|---|---|---|
| `sbom/` | syft config + how the SBOM (per image, per module) is produced | ADR 0002 §4 |
| `cbom/` | **CBOM-per-image**: `gen-cbom.py` + the active crypto `suites/` | ADR 0002 §4 + §1 |
| `cosign/` | signing/verification policy, `verify.sh`, identity options, **`KEY-CUSTODY.md`** | ADR 0002 §3 + §5 |
| `slsa/` | build-provenance generation notes | Readme "Provenance" |
| `formal/` | (pre-existing) ProVerif models of the enrollment/identity-key exchange | — |

## The supply-chain chain (one pass per artifact)

```
build  ─►  bootc container lint (hard gate)
       ─►  SBOM  (syft, CycloneDX)               ─┐
       ─►  CBOM  (gen-cbom.py: suite + SBOM)      ─┤  attached as cosign attestations
       ─►  SLSA provenance (workflow identity)    ─┘  (predicateTypes: cyclonedx / slsaprovenance)
       ─►  cosign SIGN the artifact (keyless OIDC | KMS/HSM)
       ─►  push to registry
       ─►  (OS only) bootc-image-builder → disk artifacts → sign-blob + checksums
       ─►  boot smoke-test (qemu): manifest validates + supervisor notify-ready
       ─►  health-gated promotion to the release channel
```

Every link maps to a threat-model surface (Readme "Threat model"):
- **Update / registry channel** → cosign signatures + attestation; `policy.json`
  default-reject means a tampered image won't boot-switch.
- **Supply chain** → SBOM + CBOM + SLSA provenance; reproducible builds (target).
- **Wasm sandbox escape** → orthogonal (capability grants); but a malicious *signed*
  first-party module is a stated residual risk managed by review, not eliminated.

## Crypto-agility & PQC (ADR 0002, summarised)

- The **active crypto suite** (`cbom/suites/hookprobe-pqc-hybrid-2026.yaml`) is the single
  policy source. It is mirrored into the per-device manifest `crypto` block by bootstrap,
  and into the CBOM by `gen-cbom.py` — so device crypto and the audit artifact agree.
- **Hybrid (composite)** public-key everywhere: ML-DSA-65 + Ed25519 (image/module),
  ML-KEM-768 + X25519 (TLS), LMS (boot). Symmetric/hash (AES-256, SHA-2/3) unchanged.
- A swap = publish a new named suite + regenerate CBOM + re-sign + fleet-ring rollout.
  **No call-site changes** (provider abstraction resolves primitives from `suite_id`).

## Key custody (the load-bearing operational rule)

**All image/module/firmware signing keys live OFF-device, in the offline release
HSM/KMS; devices only verify.** Stateful HBS (LMS/XMSS) **leaf-index state is managed
ONLY in the release HSM and is never forked** — reusing an index catastrophically breaks
the scheme (SP 800-208). The CI in this repo never touches the LMS key. Full rule and the
required release-time guard: **`cosign/KEY-CUSTODY.md`**.

## Consolidated TODOs (only a real CI / registry / HSM can close)

- cosign **identity**: keyless OIDC (set the cert-identity regexp + issuer) vs KMS/HSM
  key (publish public key, keep `policy.json` `keyPath`). Keep workflows, `verify.sh`,
  and `base/config/containers/policy.json` in lockstep.
- **PQC composite signing**: sigstore native support still maturing → interim dual-sign;
  flip the suite when it lands.
- **CBOM**: authoritative OIDs; confirm CycloneDX 1.6 enums; confirm trixie crypto-lib
  package names; finalize the CBOM attestation predicateType vs the SBOM.
- **SLSA**: lock the provenance mechanism to the identity model; the privileged
  `bootc-image-builder` step caps the achievable SLSA level (L2 now; L3 needs isolated
  builder).
- **LMS state guard** in the HSM-side release tooling (outside this repo).
- **TPM attestation** for fleet join (Phase 6) is not exercisable on CI runners.
