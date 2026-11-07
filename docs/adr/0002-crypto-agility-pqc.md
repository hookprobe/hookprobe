# ADR 0002 — Crypto-agility & post-quantum (PQC) layer

**Status:** ✅ Accepted (2026-06-27); **honesty pass 2026-07-05** (F5 audit) — see the per-domain
Implemented/Roadmap table in §3 and the `hookprobe:status` field every CBOM component now carries
(`security/cbom/gen-cbom.py`). Nothing in §1-§7 below was walked back; several "Now" claims that
had no code behind them were reclassified as Roadmap, and module signing's hybrid ML-DSA-65 +
Ed25519 leg — the one domain that WAS built — is now genuinely fail-closed-enforced, not just
declared.
**Date:** 2026-06-27
**Deciders:** os-architect (author), code-developer, security
**Relates to:** [ADR 0001 — Mission Control stack](0001-mission-control-stack.md) (transport TLS); `docs/architecture/Readme.md` § Post-quantum readiness; the Platform Manifest `crypto` block.

## Context

HookProbe is itself a high-value, long-lived security target, so "harvest now, decrypt later" is a *present* risk for any data with multi-year value. The standards and mandates are no longer speculative:

- **NIST finalized the PQC suite (Aug 2024):** FIPS 203 **ML-KEM** (key establishment), FIPS 204 **ML-DSA** (signatures), FIPS 205 **SLH-DSA** (stateless hash-based signatures); **SP 800-208** approves stateful hash-based signatures (**LMS/HSS, XMSS/XMSS^MT**) for firmware/software signing.
- **Timeline pressure:** RSA/ECC slated for deprecation by 2030, disallowed by 2035; EU expects high-risk migration by 2030; **NSA CNSA 2.0** requires PQC for new acquisitions in 2027, with **software/firmware signing PQC-exclusive from Jan 1, 2027**. The **EU Cyber Resilience Act** mandates crypto-agility specifically.
- **What's safe:** AES-256 and SHA-2/SHA-3 remain quantum-resistant (Grover only halves symmetric strength → AES-256 ≈ 128-bit PQ security). **Migration is a public-key problem**, not a symmetric one.

The architectural lesson is **crypto-agility — separate crypto from logic so an algorithm swap is a policy change, not a re-architecture** — not betting on one algorithm. The manifest already carries a `crypto` block and the OS already commits to "crypto is swappable" (Principle 8). This ADR specifies the layer that makes that real.

## Decision

### 1. The Platform Manifest is the single crypto-policy source of truth

The signed manifest's `crypto` block declares the **active algorithm set** for every domain; every component reads it and **no component hard-codes an algorithm**. A swap is an edit to this policy + a re-sign + a regenerated CBOM — never a code change.

```yaml
crypto:
  agility: true
  suite_id: "hookprobe-pqc-hybrid-2026"     # named, versioned suite
  module_signing: ["ml-dsa-65", "ed25519"]  # IMPLEMENTED — hybrid, both legs fail-closed-enforced
  image_signing:  ["ecdsa-p256"]            # IMPLEMENTED — real mechanism: cosign KEYLESS (Fulcio/Rekor), not PQC
  boot_signing:                             # TIER-SPLIT (ADR 0043):
    heqk_rpi_native: ["ed25519","slh-dsa-sha2-128s"]  # IMPLEMENTED — hboot hybrid boot signing, STATELESS hash-based (FIPS 205); QEMU-green + single-run metal
    uefi_amd64:      "lms"                    # ROADMAP — stateful hash-based (SP 800-208), no measured-boot signing code on this tier yet
  tls_kex:        ["ml-kem-768+x25519"]     # ROADMAP — no TLS/rustls stack in this tree yet
  tls_auth:       ["ml-dsa-65", "ecdsa-p256"] # ROADMAP — same, no TLS stack to carry it
  data_at_rest:   "aes-256-gcm"              # IMPLEMENTED — quantum-resistant, unchanged (LUKS2+Clevis/TPM)
  hash:           ["sha-256", "sha-384", "sha3-256"]  # IMPLEMENTED
  device_identity:["ml-dsa-65", "ed25519"]  # PARTIAL — Ed25519 software-PUF implemented; ML-DSA-65 roadmap
  cbom:           "/usr/share/hookprobe/cbom.json"
```

Every algorithm above carries an explicit `hookprobe:status: implemented | roadmap` in the
generated CBOM (`security/cbom/gen-cbom.py`'s `IMPLEMENTED_ALGOS` map is the single load-bearing
source of truth); a `roadmap` leg is counted quantum-**vulnerable** in the CBOM's rollup
regardless of the algorithm's own PQC category — an unimplemented PQC leg protects nothing.

### 2. A crypto-provider abstraction (algorithm = policy, not call-site)

The target mechanism: every crypto call site names a **purpose** ("verify a module signature"),
never an algorithm, and resolves the concrete primitive from the manifest's `crypto` block at
runtime — an algorithm swap is a policy edit, not a call-site change. **Built and enforced for
module signing today:** `crates/hookprobe-manifest/src/module_sig.rs::verify_module_for_suite`
reads the active suite's `module_signing` legs and dispatches to whichever verifier(s) they name
(`ed25519` / `ml-dsa-65`) — the reconcile path and the `--run-wasm` production path both go
through it, and neither hard-codes which legs are required. **Not yet built as ONE shared
interface across every other domain** (`kem_encap`/`kem_decap`/`aead` etc.) — those domains have
no code at all yet (§3's Roadmap rows), so there is nothing there to abstract. This ADR's original
"no component hard-codes an algorithm, enforced in review" language described the intended
end-state for the whole crypto surface; today it is true specifically of module signing, not a
blanket claim about domains with zero implementation.

### 3. Per-domain primitives (hybrid-by-default for public-key)

| Domain | Algorithm | Status | Standard | Where the **signing/private** key lives |
|---|---|---|---|---|
| **Module signing** | **composite ML-DSA-65 + Ed25519**, fail-closed (a missing/invalid ML-DSA leg refuses, never downgrades) | **✅ Implemented** — `crates/hookprobe-manifest/src/module_sig.rs` | FIPS 204 | **Release pipeline / offline HSM** — devices only **verify** |
| **OS image signing** | cosign **KEYLESS** (Fulcio-issued short-lived **ECDSA-P256** cert, Rekor log) | **✅ Implemented** (classical only — sigstore/cosign PQC signing is still maturing upstream) | FIPS 186-5 | Ephemeral, OIDC-identity-bound — no long-lived key at all |
| **Firmware / boot chain — heqk / rpi-native tier** | **composite Ed25519 + SLH-DSA-SHA2-128s** (STATELESS hash-based), fail-closed | **✅ Implemented** (QEMU-green + single-run metal — Track-C honesty) — heqk `hboot`, `fips205` + `ed25519-compact` crates | FIPS 205 | **Release pipeline / offline signer** (`~/heqk-sign` dev signer today; production custody OPEN — `docs/design/heqk-signing-identity.md`) |
| **Firmware / boot chain — UEFI / amd64 tier** | **LMS** (stateful hash-based) | ⏳ **Roadmap** — no measured-boot signing code on this tier; the key-custody design below is decided, the signing/verification itself is not built | SP 800-208 | **Release pipeline / HSM with state management** (design only, once built) |
| **Transport (fleet, control plane, Mission Control)** | **hybrid ML-KEM-768 + X25519** KEX; **hybrid ML-DSA-65 + ECDSA-P256** auth | ⏳ **Roadmap** — no TLS/rustls stack exists in this tree yet | FIPS 203 + RFC hybrids | Ephemeral on both ends (once a TLS stack lands) |
| **Device identity & attestation** | Ed25519 **software-PUF** (deterministic, re-derived from hardware fingerprints every boot, never stored) | **✅ Implemented** (`crates/hookprobe-manifest/src/identity.rs`) — the suite's **ML-DSA-65 leg for this domain is ⏳ Roadmap** (identity.rs has no PQC signing at all) | RFC 8032 | **On device.** TPM-sealed on boards WITH a TPM; a bare software-PUF (no hardware tamper-resistance) on TPM-less boards (e.g. Pi 4/5) — never claimed uniformly TPM-sealed |
| **Data at rest** (events, pcap, evidence) | **AES-256-GCM** | **✅ Implemented** (LUKS2 + Clevis/TPM sealing, `security/crypt/*.sh` + `base/scripts/*.sh`) | FIPS 197 | On device, key sealed to TPM where present |
| **Hashing / integrity** (composefs/fsverity, SBOM) | **SHA-256 / SHA-384 / SHA3-256** | **✅ Implemented** (`crates/hookprobe-manifest/src/module_sig.rs::digest_hex`) | FIPS 180/202 | n/a |

**Why hybrid (composite) for public-key:** concatenating a PQC and a classical primitive means an attacker must break **both** — this defends simultaneously against future quantum attacks *and* against immaturity bugs in young PQC implementations. Verification requires *both* signatures valid; KEX mixes both shared secrets.

### 4. CBOM per image (Cryptographic Bill of Materials)

Every build emits a **CBOM** (CycloneDX cryptographic-assets format) alongside the SBOM: every algorithm, key, certificate, and protocol the image uses, with its purpose and the manifest `suite_id`. Each algorithm component carries an explicit `hookprobe:status: implemented | roadmap` property (`security/cbom/gen-cbom.py`) — computed against `IMPLEMENTED_ALGOS`, the one place that tracks what code in this repo actually ships, cross-referenced against the SBOM's library inventory where possible. A `roadmap` entry is counted quantum-**vulnerable** in the rollup regardless of its own PQC category: an unimplemented leg protects nothing, so the CBOM never certifies resistance the device doesn't actually have. One query answers "what crypto is on this device, and is any of it quantum-vulnerable?" — directly serving SOC 2 / ISO 27001 / EU CRA evidence and the PQC migration audit, honestly.

### 5. Key custody splits stateful risk away from devices

The single biggest PQC footgun is **stateful hash-based signatures (LMS/XMSS): reusing a one-time leaf index catastrophically breaks the scheme** (SP 800-208 is emphatic). **The heqk/rpi-native boot tier sidesteps this footgun entirely by choosing a STATELESS hash-based scheme — SLH-DSA-SHA2-128s (FIPS 205) — which has no leaf-index state to track, back up, or fork.** This is a genuine security advantage over the UEFI-tier LMS roadmap and is the reason boot signing already ships on that tier without needing the stateful-key custody machinery below. This section is the CUSTODY DESIGN that will govern the UEFI-tier LMS once it is implemented (§3: UEFI-tier boot signing is Roadmap today, no code) — the design is decided now specifically so the risky part (stateful key management) never has to be improvised later:

- **Image, module, and (once built) firmware signing keys never live on devices.** They live in the offline release pipeline / HSM, which is (or, for firmware, will be) the *only* place that manages leaf state (monotonic, backed up, never forked). **Devices only verify** these — verification is stateless and safe. Module signing already follows this today (release HSM signs, devices verify both the Ed25519 and ML-DSA-65 legs).
- **On-device keys are stateless:** device identity uses Ed25519 (a deterministic software-PUF, no state — see §3; NOT ML-DSA, that leg is roadmap for this domain). A future TLS stack's ephemeral ML-KEM keys will be stateless too. So no device ever has to track HBS state.
- Secrets stay **off the image**, on the persistent data partition, sealed to the TPM where present, and rotatable — the image stays reproducible and secret-free.

## Crypto-agility mechanism — how a swap actually happens

1. Publish a new named suite (e.g. `hookprobe-pqc-2028` swapping ML-KEM-768 → ML-KEM-1024, or dropping a classical leg once PQC is trusted alone).
2. Update the manifest `crypto` block + `suite_id`; re-sign the manifest; regenerate the CBOM.
3. For module signing, the suite's `module_signing` legs directly drive which signatures `verify_module_for_suite` requires — **no call site changes** (demonstrated: an Ed25519-only suite and the hybrid suite are both registered and dispatch correctly today, `crates/hookprobe-manifest/src/module_sig.rs`). Other domains will follow the same pattern once they have code behind them.
4. Roll out through the normal fleet rings (canary → ring → fleet), health-gated. Hybrid suites mean old and new verifiers interoperate during the transition.

This tracks CNSA 2.0 / EU CRA **without re-platforming** — the entire point of agility.

## Migration phasing (maps to ADR 0001 and the mandates)

1. **Now (shipped):** hybrid composite module signing (ML-DSA-65 + Ed25519, fail-closed, both legs enforced); real cosign-keyless image signing (ECDSA-P256); **hybrid boot signing on the heqk/rpi-native tier (Ed25519 + SLH-DSA-SHA2-128s, stateless FIPS 205 — QEMU-green + single-run metal, honest Track-C status)**; CBOM emitted per build with an honest implemented/roadmap tag per algorithm. The CBOM must tag boot signing **per tier**: `implemented` on the heqk/rpi-native tier, `roadmap` (vulnerable in the rollup) on UEFI/amd64 — a single blanket "boot_signing: roadmap" would now *understate* the heqk tier and violate this ADR's own honesty bar.
2. **Roadmap, no committed date yet:** hybrid TLS (ML-KEM-768 + X25519) on the control plane — there is no TLS/rustls stack in this repo to carry it (ADR 0001's own transport work has not landed either; the earlier claim that this was "already in ADR 0001 via rustls `X25519MLKEM768`" was itself aspirational — there is no rustls dependency anywhere in this tree today); **LMS for UEFI/amd64-tier firmware/boot signing** — no code, though the key-custody design (§5) is ready for it. (The heqk/rpi-native tier already has boot signing shipped via stateless SLH-DSA — item 1 — so LMS is a UEFI-tier concern, not a universal gap.)
3. **2027 (CNSA 2.0 / firmware mandate):** PQC-exclusive firmware signing is **already met on the heqk/rpi-native tier** (SLH-DSA is a FIPS 205 PQC scheme); on **UEFI/amd64** it needs LMS to actually ship first (item 2, not yet true); begin offering PQC-only TLS suites where peers support them once a TLS stack exists.
4. **2030+:** retire classical legs from hybrids per the deprecation schedule by publishing a new suite — a policy change, not a rebuild.

## Consequences / risks

- **Stateful HBS (LMS/XMSS) state management** is the critical operational risk once boot signing is actually built — the custody DESIGN that resolves it (keeping signing off-device in an HSM-backed pipeline, §5) is decided now, ahead of the implementation, precisely so it can't be improvised under deadline later. Non-negotiable when LMS ships; not yet a live risk because there is no LMS code today.
- **Larger artifacts / handshakes.** ML-DSA-65 signatures (~3.3 KB) measurably inflate `module.mldsa.sig` vs the existing 64-byte Ed25519 signature — measured in this repo (see the code-developer report accompanying this fix); ML-KEM ciphertext (~1.1 KB) would similarly inflate a future TLS handshake, once one exists to measure.
- **PQC library/tooling maturity.** RustCrypto `ml-dsa` (FIPS 204, pure Rust, `no_std`-capable) is what this repo actually depends on for module signing today and works well; RustCrypto `ml-kem` and a hybrid-KEX-capable TLS stack (rustls or otherwise) are **not yet integrated anywhere in this tree** — that is genuinely still ahead of us, not merely "production-track and assumed done". **cosign/sigstore PQC signing is still maturing** — the interim path (and what is actually shipped) is composite/dual-signing at the module-signing layer, with image signing staying classical (cosign keyless ECDSA-P256) until sigstore's own PQC mode lands. The hybrid posture is itself the mitigation where it is implemented (classical leg holds if a PQC impl has a bug).
- **FIPS validation lag.** FIPS-validated PQC modules trail the standards; for regulated deployments, pin to validated providers (e.g. aws-lc-rs FIPS) via the `suite_id`, available on the Ubuntu Pro FIPS base.
- **Combinatorial test surface.** Hybrid suites multiply interop cases; the CBOM + named `suite_id` keep the active matrix small and explicit.

## Validation

**Done (2026-07-05, F5 audit fix):** `code-developer` dual-signed a test module (hybrid ML-DSA-65 + Ed25519, pure-Rust RustCrypto `ml-dsa`, no liboqs/C) and verified it on-device through `verify_module_for_suite` — proved fail-closed: a module missing its ML-DSA sidecar under the hybrid suite is refused (never downgraded to Ed25519-only), a bad ML-DSA signature refuses even with a valid Ed25519 one, and a registered Ed25519-only suite genuinely verifies Ed25519-only (the dispatch really is driven by the named suite, not a hardcoded assumption). Emitted a CBOM (`security/cbom/gen-cbom.py`) that tags module signing `implemented` and LMS/ML-KEM `roadmap`, with the vulnerability rollup counting the roadmap legs vulnerable. `security` should still review the key-custody split design in §5 against the eventual LMS release tooling once that ships.

**Not yet done — tracked as Roadmap (§ Migration phasing), not fabricated as complete:** bringing up the control plane over hybrid ML-KEM-768 + X25519 TLS on a Pi 5 / N100 (no TLS/rustls stack exists in this repo yet to test); implementing LMS boot signing and its state-management guard in the release tooling.

## Sources

NIST FIPS 203/204/205; NIST SP 800-208 (stateful HBS); NSA CNSA 2.0 timeline; NIST IR 8547 (transition to PQC); EU Cyber Resilience Act (crypto-agility); IETF hybrid KEM/composite-signature drafts; RustCrypto `ml-dsa` (FIPS 204, pure Rust, `no_std`-capable — the dependency this ADR's module-signing leg actually uses) / `ml-kem` (not yet integrated); aws-lc-rs FIPS; CycloneDX CBOM; sigstore/cosign PQC roadmap. (The earlier "rustls `X25519MLKEM768`" source entry is removed — this repo has no rustls dependency.)

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: ENABLES (distinct-but-co-rooted, NOT one shared key).** The implemented hybrid **ML-DSA-65 + Ed25519** module signing is pure-Rust `no_std` RustCrypto, so the *module* verifier re-hosts onto the bare-metal kernel cleanly. But heqk's `hboot` **boot** signing is a **different PQC algorithm family** — hybrid **Ed25519 + SLH-DSA-SHA2-128s** (FIPS 205, stateless hash-based, via the `fips205` + `ed25519-compact` crates), *not* ML-DSA-65 (FIPS 204, lattice, via `ml-dsa` + `ed25519-dalek`). The two keypairs are **non-interoperable**: the module verifier does **not** port into the boot verifier, and the trust chains do **not** merge into one key. They are instead **co-rooted** — unified not by a shared key but by ONE governed custody/rotation process and one release-identity record binding boot-SVN ↔ module-signing epoch. Custody access-path and the boot-key security-category choice remain **open operator-gated decisions** — see `docs/design/heqk-signing-identity.md`. Only the data-at-rest leg (LUKS2/Clevis/TPM) re-homes onto a heqk-native sealed volume. → **Phases M1/M3**.
