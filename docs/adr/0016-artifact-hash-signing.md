# ADR 0016 — Artifact-hash signing: the signature must cover the payload, not just `module.yaml`

**Status:** ✅ Accepted (2026-07-05) — implemented + adversarially audited + a CRITICAL bypass
found and remediated (Fix A/B/C + [ADR 0017](0017-authenticated-aot-cache.md)); verified green
(380 workspace tests, `--features wasm`). Was 🟡 Proposed (2026-07-04). **Read the "Errata" at the
end of this document before reading D1/D2 as originally shipped** — the traceability trail
(requirement → this ADR → audit finding → Fix A/B/C → regression tests → ADR 0017) is the point.
**Deciders:** os-architect (author), security-auditor, release-engineer, verification-engineer, code-developer.
**Relates to:** [ADR 0002](0002-crypto-agility-pqc.md) (crypto-agility; `module_signing` suite; hash alg is policy, not hardcoded), [ADR 0003](0003-platform-manifest-schema.md) (module model; `signature: required`), [ADR 0006](0006-os-hardening.md) (H3 dm-verity rootfs integrity — the block-layer complement of this ADR), [ADR 0009](0009-soc-brain-edge-cloud.md) (the `.cwasm` AOT `.sha256` sidecar this ADR reuses; the `--run-wasm` verify-before-run gate this ADR extends), [ADR 0015](0015-registry-driven-module-inclusion.md) (registry-driven staging; the `.sig`/`.wasm` files this ADR now cross-binds). Upholds the core invariant **"trust nothing unsigned"** — and closes the hole where the *unsigned thing actually executes*.

---

## Context — the signature does not cover the code

"Trust nothing unsigned" is a load-bearing invariant, but a supply-chain audit this session found that today's implementation **signs the manifest, not the payload**:

- `module_sig::module_digest()` (`crates/hookprobe-manifest/src/module_sig.rs`) computes `SHA-256(module.yaml bytes)` and **nothing else**.
- `module.sig` is a detached Ed25519 signature over *that* digest.
- `verify_module()` verifies `module.sig` over `SHA-256(module.yaml)` against the baked trust store (`/usr/share/hookprobe/trust/release.pub`, RO rootfs — unified this session).
- The executable payload is located **separately and unverified**: `wasm_loader::locate_wasm()` / `locate_executable()` resolve `<id>.wasm` (or the `.cwasm`, or a sysext loader ELF / `.bpf.o`) by path convention, with **no signature check on those bytes**.

**The attack.** An adversary who can write to `/usr/lib/hookprobe/modules/` (or the on-device AOT cache `/var/lib/hookprobe/modules-cache/`) swaps `napse.wasm` for a malicious component while leaving `module.yaml` **and** `module.sig` byte-identical. `verify_module()` still returns `Verified` — because it never hashes the `.wasm`. `supervisor::verify_signature()` returns `true`. The supervisor then runs attacker code, inside NAPSE's granted WASI capabilities, with a clean "signature: verified" line in the log. Signature verification is **theatre** for everything except the manifest.

**The hook that already exists.** The AOT path (ADR 0009) already computes `SHA-256(source .wasm bytes)` and records it in a `<id>.cwasm.sha256` sidecar; `wasm_loader::cwasm_matches_source()` recomputes and compares it to decide whether a cached `.cwasm` is still bound to the on-disk `.wasm`. That is exactly the hash we need to fold into the *signature*. We are not inventing a hashing step — we are making the **manifest carry that digest** so the existing `module.sig` transitively covers the payload, and making the supervisor **check it before execute**, not just before AOT-cache reuse.

Two independent integrity layers are in play and must not be conflated:

| Layer | Protects | Scope | Failure mode | Status |
|---|---|---|---|---|
| **Artifact-hash signing** (this ADR) | the *specific payload a module declares* | per-module, cryptographic, tied to the release key | fail-closed refuse-to-load | **missing today** |
| **dm-verity on `/usr`** (ADR 0006 H3) | *every block* of the RO rootfs | whole-filesystem, block-layer | fail-closed kernel EIO | Pi path `verified`/`enforced`; other platforms `none` |

This ADR delivers the first (defense against a tampered payload the manifest is supposed to pin) and **recommends** the second as defense-in-depth (so rootfs-resident payloads cannot be swapped at the block layer at all).

---

## Decision

### D1 · `module.yaml` carries the payload digest(s); one signature covers everything

Extend the module manifest with an **`artifacts:` block** naming every shipped payload file and its digest. We choose **digest-in-manifest** (in-toto / OCI-descriptor style) over per-artifact detached signatures: **one signature over the manifest transitively covers all payloads**, there is exactly one trust decision per module, and it composes with ADR 0015's single-`.sig`-per-module staging convention. Per-artifact `.sig` files would multiply the trust surface and the staging plan for no gain.

The digest algorithm is **named per entry**, never hardcoded — aligning with ADR 0002 (`crypto.module_signing` is policy). `sha256` is today's default; `sha384`/`sha3-256` are drop-in by naming them. Multiple digests per artifact are allowed (agility during a hash migration: verifier accepts a match on **any** listed alg it supports).

**Before** (`modules/napse/module.yaml`, today):

```yaml
id: napse
version: 2.4.1
runtime: wasm
artifact: registry.hookprobe.com/modules/napse:2.4.1
requires:
  capabilities: [soc, ids]
  min_memory_mb: 256
grants:
  - read: /var/lib/hookprobe/flows
  - wasi-nn: cpu
resources: { cpu_pct: 50, memory_mb: 256, epoch_ms: 50 }
signature: required
```

**After** (adds the `artifacts:` block; everything else unchanged):

```yaml
id: napse
version: 2.4.1
runtime: wasm
artifact: registry.hookprobe.com/modules/napse:2.4.1
requires:
  capabilities: [soc, ids]
  min_memory_mb: 256
grants:
  - read: /var/lib/hookprobe/flows
  - wasi-nn: cpu
resources: { cpu_pct: 50, memory_mb: 256, epoch_ms: 50 }

# Payload digests — the signature over this module.yaml transitively covers these
# files. The supervisor MUST recompute and match each before executing (D2).
# `alg` is named (ADR 0002 crypto-agility), never hardcoded. `role` tells the
# loader which file this is (the executable vs. an auxiliary object).
artifacts:
  - path: napse.wasm            # resolved relative to the module's install dir
    role: executable            # executable | bpf-object | loader | data
    digest:
      alg: sha256
      value: "3f6b…<64 hex>…a91c"

signature: required             # the .sig now protects code, not just metadata
```

Sysext/native example — a loader ELF plus a BPF object, both pinned:

```yaml
# modules/napse-quarantine/module.yaml (excerpt)
runtime: sysext
artifacts:
  - path: /usr/lib/hookprobe/bin/napse-quarantine
    role: loader
    digest: { alg: sha256, value: "…" }
  - path: /usr/lib/hookprobe/bpf/quarantine.bpf.o
    role: bpf-object
    digest: { alg: sha256, value: "…" }
signature: required
```

`ModuleDef` (`crates/hookprobe-manifest/src/module_def.rs`) gains:

```rust
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModuleDef {
    // …existing fields…
    #[serde(default)]
    pub artifacts: Vec<ArtifactDigest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArtifactDigest {
    pub path: String,           // relative to install dir, or absolute for sysext
    #[serde(default)]
    pub role: ArtifactRole,     // executable | bpf-object | loader | data
    pub digest: Digest,         // possibly a list in a future migration window
}

#[derive(Debug, Clone, Deserialize)]
pub struct Digest { pub alg: String, pub value: String }  // alg NAMED, not enum-locked
```

### D2 · Supervisor enforcement — recompute-and-match, fail-closed, before execute

Signature verification proves `module.yaml` (and therefore its `artifacts:` block) is authentic. That is necessary but **not sufficient**: the supervisor must then prove the file on disk **matches the digest the authentic manifest pins**. Order is load-bearing: **verify sig → (manifest now trusted) → recompute payload hash → compare → only then execute.**

This slots into the existing `--run-wasm` gate in `supervisor/src/main.rs` (the block at ~L353–381 that already does the sig gate), immediately **after** `locate_executable()` resolves the payload (~L385) and **before** the module is instantiated/run. The identical check is added to the reconcile load path (the `verify_module` loop at ~L1120) so the two run paths never diverge (same discipline ADR 0009 established for the sig gate).

Pseudocode (the new gate, verbatim intent):

```rust
// … after the existing signature gate has PASSED (def.sig_verified == Some(true)
//    or signature != "required"), and after locate_executable() resolves `exec`:

fn verify_artifact_digests(def: &ModuleDef, install_dir: &Path) -> Result<()> {
    // Release builds: a signature:required module with NO artifacts block is a
    // HARD FAIL — an unprotected payload must never execute (D5).
    if def.signature == "required" && def.artifacts.is_empty() {
        #[cfg(not(debug_assertions))]
        bail!("refusing {id}: signature:required but module.yaml pins no artifact \
               digest — payload is unprotected (ADR 0016). Re-sign with builder/sign-release.sh.");
        #[cfg(debug_assertions)]
        eprintln!("warning: {id} pins no artifact digest — payload UNPROTECTED (dev only).");
    }

    for a in &def.artifacts {
        let file = resolve_artifact_path(&a.path, install_dir); // rel → install dir; abs as-is
        let bytes = fs::read(&file)
            .with_context(|| format!("{id}: artifact {} not found for digest check", a.path))?;
        let actual = match a.digest.alg.as_str() {          // crypto-agile: NAMED alg
            "sha256"    => hex::encode(Sha256::digest(&bytes)),
            "sha384"    => hex::encode(Sha384::digest(&bytes)),
            "sha3-256"  => hex::encode(Sha3_256::digest(&bytes)),
            other       => bail!("{id}: unsupported digest alg '{other}' (ADR 0002 policy)"),
        };
        if !actual.eq_ignore_ascii_case(a.digest.value.trim()) {
            // FAIL-CLOSED: refuse to load + emit an evidence event (tamper signal).
            emit_evidence(EvidenceEvent::ArtifactTamper {
                module: id, path: a.path, expected: a.digest.value, actual,
            });
            bail!("refusing {id}: artifact {} digest MISMATCH — payload tampered \
                   (expected {}, got {}). ADR 0016 fail-closed.", a.path, a.digest.value, actual);
        }
    }
    Ok(())
}
```

Placement and rules:

- **Executable role is mandatory-checked.** For `runtime: wasm`, the file `locate_executable()` resolved (the `.wasm` source; if it selected a `.cwasm`, the `.wasm` the sidecar binds to) must have `role: executable` and match. A `.cwasm` remains bound to the `.wasm` by its existing sidecar (ADR 0009) — so pinning the `.wasm` transitively pins any AOT cache derived from it; **no separate `.cwasm` digest is needed** (and the AOT cache stays on the writable partition, correctly outside the signed manifest). **⚠️ Superseded by [ADR 0017](0017-authenticated-aot-cache.md):** this reasoning was wrong — the sidecar is attacker-forgeable on the writable partition, so the `.cwasm` IS now pinned as a `role: aot` entry inside the signed manifest. See the Errata/Addendum below.
- **Fail-closed, always.** A missing file, an unreadable file, an unsupported alg, or a mismatch → refuse to load, non-zero exit on `--run-wasm`, `Refused` outcome in reconcile, and an `ArtifactTamper` evidence event (surfaced in the Detect/Investigate workspaces — a payload swap is a security incident, not a config warning).
- **No `--allow-unsigned` bypass for digests.** `--allow-unsigned` (dev escape hatch) already lets an unsigned module run; it must **not** silence a digest *mismatch* on a module that *does* carry an `artifacts:` block, because a mismatch is affirmative evidence of tampering, not merely an absence of signing.

### D3 · Builder ordering — hash the built artifact, then sign

The digest must be **populated before signing**, so the signature covers the true bytes and the build is deterministic. `builder/sign-release.sh` (which drives `hookprobe-supervisor --sign-modules` → `module_sig::dev_sign_all`) changes to a strict two-phase order **per module**:

```
1. BUILD    compile the payload (cargo → .wasm / loader ELF / .bpf.o) into its final bytes.
2. DIGEST   for each declared artifact: compute digest(alg, bytes) → write value into
            module.yaml's artifacts[].digest.value   (in place, canonical formatting).
3. SIGN     SHA-256(module.yaml) → Ed25519/ML-DSA sign → module.sig     (per ADR 0002 suite).
```

Consequences of the ordering:
- Signing is the **last** step and is over the *final* `module.yaml` — so `verify_module()` (unchanged) now transitively authenticates the payload digests.
- `module_digest()` still hashes `module.yaml` bytes — **no change to the signature mechanism**, only to what `module.yaml` now contains. This keeps the crypto-agility seam (ADR 0002) intact: swapping the *signature* alg and the *digest* alg are independent policy edits.
- A new subcommand fills digests: `hookprobe-supervisor --write-artifact-digests <modules>` (mirrors `--sign-modules`), run by `sign-release.sh` **before** the sign step. CI asserts the two are never inverted (a digest written *after* signing would invalidate the `.sig` — caught by a post-sign `verify_module` gate in `builder/release-pass.sh`).

### D4 · dm-verity on `/usr` — recommend by default, coordinate via ADR 0006, do not turn on here

D1/D2 stop a *manifest-inconsistent* payload from running. dm-verity stops a payload from being *swapped at the block layer at all*, and covers files this ADR's manifest does not enumerate. Current status (grounded, not assumed): `base/scripts/rootfs-integrity-check.sh` already reports three postures — `enforced` (root served through a live dm-verity target), `verified` (metadata present, one-shot `veritysetup verify` matched), `none` (no metadata: pre-H3 image / non-Pi UEFI-SB+TPM platforms). The Pi arm64 path ships the `/boot` verity anchor; **cloud/N100/VM images are `none` today.**

**Recommendation:** make `enforced` the default for `/usr` across all platforms. **This ADR does not flip it** — verity-boot is an initramfs + bootloader + image-assembly change owned by ADR 0006 (H3) and the mkosi/Containerfile boot chain, and turning it on without target-hardware boot verification would violate the build-honesty rule. This ADR **records the dependency and the recommendation**, and asserts that artifact-hash signing (D1/D2) is the platform-independent floor that holds **even where verity is `none`** (VM/cloud). Follow-up: ADR 0006 revision to extend verity from `verified` to `enforced` on the non-Pi image paths. The two are complementary, not redundant: verity without artifact-signing can't tell a legitimately-updated payload from a tampered one across an OTA delta; artifact-signing without verity can't protect files outside the registry. Ship both.

### D5 · Migration & compatibility — missing digest is a hard fail in release, warn in dev

The dangerous silent state is "signed manifest, unprotected payload." Policy by build profile:

- **Release build / signed image:** a module with `signature: required` and an **empty `artifacts:` block** is a **hard load fail** (D2 pseudocode, `#[cfg(not(debug_assertions))]`). No unprotected payload executes on a shipping device. `builder/verify-staging.sh` (ADR 0015 D3 gate) gains a check: every `signature: required` module **must** declare at least one `role: executable` artifact digest, else the build fails — so this is caught at bake time, not first boot.
- **Debug / dev workspace:** the same condition **warns** (so `cargo run -- --run-wasm napse` against unsigned local builds still works during development), but the warning is loud and names ADR 0016.
- **Rollout:** because every current `modules/*/module.yaml` lacks the block, D3's `--write-artifact-digests` pass must run over the whole registry in the same release that lands this ADR; the D5 release-gate then guarantees no shipped module regresses to unprotected. There is **no** grandfathering flag — an image either pins all payloads or fails its release pass.

---

## Files that will change

**Schema / types**
- `crates/hookprobe-manifest/src/module_def.rs` — add `artifacts: Vec<ArtifactDigest>`, `ArtifactDigest`, `ArtifactRole`, `Digest` (alg named).
- `crates/hookprobe-manifest/src/module_sig.rs` — **no change to the sig mechanism** (`module_digest` still hashes `module.yaml`); add a public `verify_artifact_digests(def, install_dir)` helper (multi-alg, fail-closed) reused by both run paths.
- `manifest/schema/` (module schema, if a JSON schema for `module.yaml` exists) — add the `artifacts` block; make it required-when-`signature: required`.

**Supervisor enforcement**
- `supervisor/src/main.rs` — call `verify_artifact_digests()` in the `--run-wasm` gate (after `locate_executable`, ~L385, before instantiate) **and** in the reconcile load loop (~L1120). Emit `ArtifactTamper` evidence on mismatch; wire the `--allow-unsigned` exemption to sig-absence only, never digest-mismatch.
- `supervisor/src/wasm_loader.rs` — expose the source-`.wasm` path that a resolved `.cwasm` binds to, so the executable-role check hashes the right file; add `Sha384`/`Sha3_256` behind the alg switch (Cargo dep).

**Builder / release**
- `builder/sign-release.sh` — enforce build → digest → sign ordering; run `--write-artifact-digests` before `--sign-modules`.
- new supervisor subcommand `--write-artifact-digests <modules>` (in `supervisor/src/main.rs` + a `module_sig::write_digests()` helper) — compute each declared artifact's digest and write it into `module.yaml` in place.
- `builder/release-pass.sh` — post-sign gate: re-run `verify_module` **and** `verify_artifact_digests` over the whole registry; fail if any `signature: required` module lacks an `executable` digest or if a digest post-dates its signature.
- `builder/verify-staging.sh` (ADR 0015 D3) — add the "every `signature: required` module pins ≥1 `role: executable` digest" assertion.

**Modules (data)**
- `modules/*/module.yaml` — add the `artifacts:` block to every signed module (populated by `--write-artifact-digests`; `napse`, `qsecbit`, `dnsxai`, `aegis-guard`, `senzorium-flow`, `napse-capture`, `napse-quarantine`, `host-telemetry`, `evidence`, `ovs` where it ships a payload).

**Docs**
- `docs/adr/0006-os-hardening.md` — follow-up note: extend verity from `verified` to `enforced` on non-Pi image paths (D4).
- `docs/architecture/Readme.md` (supply-chain section) — state that the module signature covers the payload digest, not just the manifest.

---

## Alternatives considered

- **Per-artifact detached signatures (`napse.wasm.sig`).** Rejected: multiplies the trust surface and the staging plan, and every payload needs its own verify step. Digest-in-manifest gives one signature, one trust decision, and matches OCI/in-toto. (The mechanism is equivalent in strength; the manifest sig already exists.)
- **Sign the OCI artifact with cosign and trust the registry digest end-to-end.** This is the *production* target (ADR 0002 notes cosign over the OCI `.wasm`), and it subsumes D1 for registry-pulled modules. But devices run **air-gapped and standalone by default** (core invariant) and load payloads from the **RO rootfs**, not always from a live registry — so a device-local, offline, manifest-pinned digest check is required regardless. D1/D2 *are* the offline projection of the cosign chain; when full sigstore lands, the manifest digest is verified against the signed OCI descriptor and the mechanism is unchanged.
- **Rely on dm-verity alone.** Rejected as sufficient: verity is `none` on cloud/N100/VM today, cannot distinguish a legitimate OTA payload update from tampering, and does not cover the writable AOT cache. Ship it as defense-in-depth (D4), not as the primary control.
- **Fold the `.cwasm` into the signature too.** ~~Rejected: the `.cwasm` is device-and-wasmtime-specific, produced on-device on the writable partition (ADR 0009) — it can't be pre-signed off-device. Pinning the source `.wasm` (which the `.cwasm` sidecar already binds to) covers it transitively without dragging build-time state into the signed manifest.~~ **Reversed by [ADR 0017](0017-authenticated-aot-cache.md):** the `.cwasm` is now precompiled per-arch at *build* time into the RO rootfs and pinned as a `role: aot` entry — the "produced on-device on the writable partition" premise no longer holds, and transitive pinning of the `.wasm` was proven insufficient (the audited bypass).

---

## Consequences

**Positive.** "Trust nothing unsigned" becomes true of the *code that runs*, not just its metadata — the payload-swap attack is defeated with a fail-closed refuse-and-alert. Reuses the existing `.cwasm` hashing hook and the existing `module.sig` mechanism, so the crypto seam (ADR 0002) is untouched. Tamper attempts become **evidence-graph events**, not silent successes. The offline/air-gapped device gets the same protection as a registry-pulled one.

**Residual risks / costs.** (1) Every signed module must be re-digested and re-signed in the landing release; the D5 gate makes a regression a hard build failure but the one-time migration touches all `module.yaml`s. (2) A load-time hash of the payload adds cold-start cost — bounded (SHA-256 of a few-hundred-KB `.wasm` is sub-millisecond; well inside the 1–5 ms cold-start budget) and only on the JIT/first-load path; the `.cwasm` fast path already hashed the same bytes. **This sub-millisecond claim was WRONG for the compile-from-verified-bytes path — see Errata.** (3) dm-verity `enforced` on non-Pi platforms is **deferred** to ADR 0006 — until then those images rely on artifact-hash signing plus filesystem permissions, not block-layer integrity; this is stated honestly, not papered over. (4) Multi-alg digest lists during a hash migration widen the verifier's accept set — must be time-boxed and CBOM-tracked so a deprecated alg is not silently accepted forever.

---

## Errata (2026-07-05) — a security audit found the D1/D2 implementation had a CRITICAL bypass

The first implementation of D1/D2 (`module_sig::verify_artifact_digests`, `supervisor/src/main.rs`'s
`--run-wasm`/reconcile gates) shipped with two real holes an audit caught before this ADR's status
left "Proposed":

- **Finding 1 (CRITICAL) — the digest gate hashed the wrong bytes.** `verify_artifact_digests`
  re-opened the artifact path (the source `.wasm`) to hash it, but the file Wasmtime actually
  **executed** could be a `.cwasm` from the writable AOT cache
  (`/var/lib/hookprobe/modules-cache/`), trusted via `Module::deserialize_file` whenever its
  sidecar `.cwasm.sha256` matched the `.wasm` currently on disk (ADR 0009). An attacker with `/var`
  write access could swap in an evil `.cwasm` and leave the sidecar claiming the (untouched, real)
  `.wasm`'s hash — the digest check passed (it hashed the real file), Wasmtime ran the evil one. No
  key was forged; the check simply never looked at the bytes that ran.
- **Finding 3 — no path-binding cross-check.** `verify_artifact_digests` iterated whatever
  `artifacts:` declared but never confirmed the file about to execute was actually one of those
  declared entries — an `artifacts:` block naming only a `role: data` file (digest matching) passed
  cleanly while the real, unpinned `.wasm` executed unchecked.
- **Finding 2 (HIGH) — wasm-only coverage.** The gate never covered the sysext/native start paths
  this repo owns (the eBPF loaders) or container/systemd-launched paths.

**Fix shipped (2026-07-05), `code-developer`:**

- **Fix A (closes Finding 1).** `supervisor/src/wasm_loader.rs::load_module_gated` — for
  `signature: required` modules, the loader reads the pinned `.wasm` bytes **exactly once**,
  verifies those bytes (`hookprobe_manifest::module_sig::verify_executable_binding`), and compiles
  directly via `Module::from_binary`. `Module::deserialize_file` on a `.cwasm` is **unreachable**
  for a signed module, however `locate_executable` resolved it — the writable-partition AOT fast
  path is used ONLY for `signature: unsigned` (dev-only) modules, which never claimed this
  protection. **Measured cold-start cost of this safe default is FAR from the "sub-millisecond"
  claim above**: JIT-compiling napse/qsecbit/dnsxai/aegis-guard from verified bytes measured
  **~1.0–2.0 seconds** per module on this dev box (Cranelift optimizing codegen for a few-hundred-KB
  module), versus **~1.5–2.2 ms** via the (now-untrusted-for-signed-modules) `.cwasm` deserialize
  path. This is shipped anyway as the correct, fail-closed default (security over a "1–5 ms"
  cold-start figure that was never safe in the first place) — but it is a REAL regression against
  the ADR 0009 cold-start target that needs a follow-up decision, not a number to quietly live with.
  **Escalated to os-architect:** a device-sealed-AOT scheme (MAC the `.cwasm` bytes with a key a
  local `/var`-write attacker cannot forge — TPM-sealed where present, e.g. Pi5/RK3588/N100; some
  boot-derived-key equivalent where it is not, e.g. Pi4 with no TPM) is the likely follow-up ADR;
  code-developer did not invent that keying scheme per this task's explicit instruction to escalate
  instead.
- **Fix B (closes Finding 3).** `module_sig::verify_executable_binding` additionally requires the
  resolved, canonicalized (symlink-free, non-traversal) executable path to match a declared
  `role: executable`/`role: loader` artifact that was itself digest-checked; refuses otherwise.
  Mirrored at build time: `builder/verify-staging.sh` check #6 and `builder/release-pass.sh`'s
  post-sign gate now assert every `signature: required` module's executing-payload artifact path
  resolves to a path the staging plan actually stages.
- **Fix C (partially closes Finding 2).** `modules/napse-quarantine/loader` (the highest-privilege
  native start path this repo owns — `bpf(2)` + `CAP_NET_ADMIN`, Ring-0 TC-bpf) now calls
  `module_sig::verify_artifact_digests` against its own (RO-rootfs) `module.yaml` for its loader
  binary AND its `.bpf.o`, fail-closed, before ever loading/attaching either. `napse-capture`'s
  staged binary (`napse-dpi`) does not load a `.bpf.o` at all today (AF_PACKET only — the true XDP
  loader path is tracked-but-not-staged per that module's own `module.yaml` note), so there was no
  eBPF-load call site to gate there yet. **Container/sysext paths systemd launches directly are
  NOT yet covered** (the supervisor has no runtime path that starts those — see `main.rs`'s
  pre-existing TODO) — this remains an explicit, tracked follow-up, not a claimed guarantee. The
  enforced guarantee TODAY is: **wasm modules (via the supervisor) + the native eBPF loaders this
  repo owns (napse-quarantine)**.

Regression tests proving the fix: `crates/hookprobe-manifest/src/module_sig.rs`
(`executable_binding_tests` module — the `.cwasm`-swap attack, the data-only-artifacts-block
refusal, the `..`/symlink rejection), `supervisor/src/wasm_loader.rs`
(`cwasm_swap_attack_is_refused_by_the_gated_load_path`, reproducing the exact attack end-to-end
with a real Wasmtime engine and a genuinely different swapped-in module, plus
`fix_a_cold_start_regression_measurement`), and `modules/napse-quarantine/loader/src/main.rs`
(`adr0016_tests`, including a tampered-`.bpf.o` refusal).

## Addendum (2026-07-05) — the Fix A cold-start regression is paid down by ADR 0017

The escalation at the end of Fix A above ("a device-sealed-AOT scheme... is the likely follow-up
ADR") is resolved: **[ADR 0017](0017-authenticated-aot-cache.md)** moves the `.cwasm` INSIDE the
trust boundary instead — built at image-build time (per arch, native precompile, no cross-AOT),
shipped in the RO rootfs, digest-pinned as a new `role: aot` entry in the SAME signed
`module.yaml` this ADR's `artifacts:` block already introduced (D1), verified by
`module_sig::verify_aot_binding` before `Module::deserialize`. Fix A's verified-JIT path
(`Module::from_binary` on the ADR 0016-verified `.wasm` bytes) remains exactly as shipped here —
it is now the FLOOR ADR 0017 falls back to on any doubt (absent/wrong-arch/digest-mismatched
blob, or a Wasmtime version/config-drift `deserialize` error), never removed, never bypassed.
Measured restoration: ~3.5–22 ms per module (vs. Fix A's ~0.9–1.8 s), see ADR 0017's own
measurement section and `wasm_loader::tests::adr0017_cold_start_measurement_vs_fix_a_baseline`.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL / ENABLES.** The `artifacts:`-digest, verify-before-execute, fail-closed discipline is portable Rust and *strengthens* a microkernel trust story (it composes with heqk's capability wall). Only the enforcement call-sites (supervisor/Wasmtime/eBPF loaders) re-wire. It is a load-bearing half of ADR 0043 D2's portability contract. → **Phases M2/M5**.
