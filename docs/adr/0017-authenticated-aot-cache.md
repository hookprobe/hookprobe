# ADR 0017 — Authenticated AOT cache: restore fast cold-start without reintroducing the `.cwasm`-swap bypass

**Status:** ✅ Accepted (2026-07-05) — implemented + verified green (380 workspace tests,
`--features wasm`; cold-start restored to ~3.5–5.2 ms release per module, from Fix A's ~1 s).
The one honest **Blocker** below (Wasmtime CLI/embedded version drift) is reconciled to `27.0.0`
with a build-time assertion in `base/Containerfile` (see "Blocker found" — now resolved).
Was 🟡 Proposed (2026-07-05).
**Deciders:** os-architect (author), security-auditor, release-engineer, verification-engineer, code-developer.
**Relates to:** [ADR 0016](0016-artifact-hash-signing.md) (artifact-hash signing — the manifest-digest mechanism this ADR *extends*, not replaces; its Errata/Fix A is the regression this ADR pays down), [ADR 0009](0009-soc-brain-edge-cloud.md) (the AOT `.cwasm` fast path + `hookprobe-precompile.service` + the ~1–5 ms cold-start target this ADR restores), [ADR 0002](0002-crypto-agility-pqc.md) (crypto-agility; `module_signing`/digest alg is policy, named not hardcoded), [ADR 0006](0006-os-hardening.md) (H3 dm-verity — the block-layer complement; this ADR is deliberately *independent* of it), [ADR 0003](0003-platform-manifest-schema.md) (module model; `signature: required`, manifest `arch`), [ADR 0015](0015-registry-driven-module-inclusion.md) (registry-driven staging; the single-`.sig`-per-module convention this ADR preserves). Upholds **"trust nothing unsigned"** *and* the product's stated **"~1–5 ms cold start"** (docs/Readme.md) — today you can have one or the other, not both.

> **Extended (2026-07-08):** [ADR 0021 Amendment D6](0021-multiarch-native-artifact-digests.md#amendment-2026-07-08--d6--the-cpu-micro-tier-qualifier-for-role-aot-a76-selection) adds a `cpu:` micro-tier qualifier to `role: aot` (e.g. `cpu: cortex-a76`), a second selection dimension alongside `arch`. `wasm_loader::load_module_gated` now selects `<id>.a76.cwasm` when the signed manifest's `hardware.cpu.tier` is `cortex-a76` (rpi5/rk3588) AND the signed A76 digest verifies, failing closed to the A72-safe baseline (never an A76 blob on an A72), then to verified JIT — closing the "signed A76 bytes shipped but never selected" gap.

---

## Context — Fix A traded a ~1000× cold-start regression for security, correctly, but that bill is now due

ADR 0016 Fix A (2026-07-05) closed a CRITICAL local-privilege bypass: the writable AOT cache `/var/lib/hookprobe/modules-cache/<id>.cwasm` (Wasmtime-precompiled **native code**) was executed via `Module::deserialize_file` while only the source `.wasm` was digest-checked. A `/var`-write attacker could swap the `.cwasm` for arbitrary native code and leave the sidecar `.cwasm.sha256` claiming the untouched real `.wasm`'s hash — the digest gate passed (it hashed the real file), Wasmtime ran the evil bytes, log said "signature: verified." (Reproduced end-to-end in `wasm_loader.rs::cwasm_swap_attack_is_refused_by_the_gated_load_path`.)

Fix A's remedy: for `signature: required` modules, `wasm_loader::load_module_gated` reads the pinned `.wasm` bytes **exactly once**, verifies those bytes (`module_sig::verify_executable_binding`), and compiles via `Module::from_binary` **every boot**. `Module::deserialize_file` on any `.cwasm` is unreachable for a signed module. Safe — but **measured** on the dev box (`fix_a_cold_start_regression_measurement`):

| Path | Cold start (per module) |
|---|---|
| `.cwasm` deserialize (AOT, now untrusted-for-signed) | **~1.5–2.2 ms** |
| Fix A: `from_binary` JIT from verified bytes (Cranelift optimizing codegen, few-hundred-KB module) | **~1.0–2.0 s** |

That is a **~1000×** regression, per module (napse, qsecbit, dnsxai, aegis-guard, …), on every service start / restart / OS upgrade — directly undercutting the "~1–5 ms cold start" claim in `docs/Readme.md` and ADR 0009. On a Pi-class box starting a dozen modules, that is seconds of avoidable CPU on every boot and every reconcile restart. Fix A escalated exactly this to os-architect. This ADR is that decision.

**The root cause is a location error, not a hashing error.** The `.cwasm` was untrustworthy *because it lived on a writable partition and was produced on-device after the signature was made* — outside the signed manifest's reach. Fix A responded by throwing the `.cwasm` away entirely. The correct fix is to move the `.cwasm` **inside** the trust boundary: produce it at **build time**, ship it in the **read-only rootfs**, and pin its digest in the **same signed `module.yaml`** ADR 0016 already covers — so deserializing it is exactly as trustworthy as compiling the `.wasm`, and ~1000× faster.

**A key enabling fact, verified this session.** The on-device supervisor and the build-stage supervisor are both compiled from the **same `Cargo.lock`** (`wasmtime 27.0.0`, `supervisor/Cargo.toml: wasmtime = "27"`) through the **same** `base/Containerfile` stage `build`, which runs **as the target platform** (`--platform linux/${TARGETARCH}`, QEMU-emulated in CI). So a `.cwasm` precompiled in that stage is (a) produced by the *identical* Wasmtime version + `engine_config()` the device will deserialize with, and (b) already **native to the target arch** — no `Config::target(<triple>)` cross-AOT, which was the "too fragile to validate without target hardware" objection that killed build-time precompile in ADR 0009. The QEMU-emulated container *is* the target arch; Cranelift emits target-native code as data regardless of what CPU the compiler itself runs on. **The original objection no longer applies under the emulated-target build the repo already uses.**

**One honest blocker (below, "Blocker").** `base/Containerfile` pins the *standalone CLI* `wasmtime` at `29.0.1`, while the *embedded library* that produces and consumes every `.cwasm` is `27.0.0` (Cargo.lock). These never interoperate on `.cwasm` (only the embedded lib touches AOT blobs), but the drift must be reconciled and CI must assert build-stage == device embedded Wasmtime, or Approach A silently degrades to the JIT fallback on every load.

---

## Decision

Adopt **Approach A — build-time precompile into the RO rootfs, digest pinned in the signed manifest.** Approach B (device-key MAC over a writable `.cwasm`) is rejected (see Alternatives). The `.cwasm` becomes a first-class, signature-covered payload, exactly like the `.wasm`.

### D1 · `module.yaml` pins the AOT blob too — a new `role: aot`, arch-qualified, under the SAME signature

Extend ADR 0016's `artifacts:` block with an AOT entry per built arch. One `module.yaml`, one `module.sig` (ADR 0015 preserved) — the AOT blob rides the *same* transitive signature the `.wasm` already does.

```yaml
# modules/napse/module.yaml (excerpt) — ADR 0016 entry unchanged; ADR 0017 adds role: aot
artifacts:
  - path: napse.wasm            # arch-independent source — one digest, all arches (ADR 0016)
    role: executable
    digest: { alg: sha256, value: "0788…2544" }

  # ADR 0017 — the build-time AOT blob. `arch` qualifies which image ships & checks it.
  # The device deserializes ONLY the entry whose `arch` == manifest.platform.arch; the
  # other-arch entries are inert signed metadata (a given image ships one arch's .cwasm).
  - path: napse.cwasm
    role: aot
    arch: arm64                 # arm64 | amd64 | riscv64
    digest: { alg: sha256, value: "<sha256 of the arm64 .cwasm bytes>" }
  - path: napse.cwasm
    role: aot
    arch: amd64
    digest: { alg: sha256, value: "<sha256 of the amd64 .cwasm bytes>" }

signature: required
```

`ArtifactDigest` (`crates/hookprobe-manifest/src/module_def.rs`) gains an optional arch qualifier; `ArtifactRole` gains `Aot`:

```rust
pub enum ArtifactRole { Executable, BpfObject, Loader, Data, Aot }  // + Aot (kebab: "aot")

pub struct ArtifactDigest {
    pub path: String,
    #[serde(default)] pub role: ArtifactRole,
    #[serde(default)] pub arch: Option<String>,   // NEW: None = arch-independent (.wasm); Some for aot
    pub digest: Digest,                            // named alg — ADR 0002, unchanged
}
```

**Why arch-qualified entries in one signed manifest, not per-arch `.sig` files.** The `.wasm` is arch-independent (one digest covers all arches); the `.cwasm` is arch-specific. Keeping one `module.yaml`/one `.sig` (ADR 0015's invariant) means enumerating each arch's AOT digest inside the single signed document. The cost is a **build-ordering change**: all target arches' `.cwasm` digests must be collected *before* the one signing step (D3). Per-arch detached `.sig`s were rejected for the same reason ADR 0016 D1 rejected them — multiplied trust surface, multiplied staging plan.

### D2 · Supervisor load path — verified fast path first, verified-JIT fallback, never an unauthenticated `.cwasm`

`load_module_gated` for `signature: required` keeps Fix A's discipline (read-once, verify-then-load, never a second open between check and load) and adds an authenticated fast path **in front of** the JIT fallback. The writable `/var` AOT cache remains **unreachable** for signed modules.

```rust
// signature: required — ADR 0016 Fix A verified-JIT is the FLOOR; ADR 0017 adds a verified AOT fast path.
fn load_module_gated(engine, exec, def, install_dir, events) -> Result<Module> {
  if def.signature == "required" {
    // (1) ADR 0016 unchanged: read the pinned .wasm ONCE, verify path-binding + digest.
    let wasm_bytes = read_once(exec.source_wasm());
    module_sig::verify_executable_binding(def, install_dir, exec.source_wasm(), &wasm_bytes, events)?;

    // (2) ADR 0017 fast path: an AOT blob in the RO ROOTFS (never /var), matching THIS arch,
    //     whose bytes match the signed `role: aot` digest for this arch.
    if let Some(aot) = locate_rootfs_aot(def, install_dir, manifest_arch()) {      // RO /usr path only
        let aot_bytes = read_once(&aot);                                            // read ONCE
        if module_sig::verify_aot_binding(def, manifest_arch(), &aot, &aot_bytes, events).is_ok() {
            // deserialize the VERIFIED IN-MEMORY bytes — NOT deserialize_file, no second open.
            match unsafe { Module::deserialize(engine, &aot_bytes) } {
                Ok(m) => return Ok(m),                                              // ~2 ms, authenticated
                Err(e) => warn!("aot deserialize failed ({e:#}) — Wasmtime version/config \
                                 drift? falling back to verified JIT"),             // fail-closed to (3)
            }
        } // digest mismatch → fall through to (3); NEVER deserialize an unverified/mismatched .cwasm
    }

    // (3) Fallback = the ADR 0016 Fix A floor: compile the ALREADY-VERIFIED .wasm bytes. Slow, safe.
    return Module::from_binary(engine, &wasm_bytes);
  }

  // signature: unsigned (dev only) — UNCHANGED from Fix A: /var .cwasm fast path stays allowed.
  module_sig::verify_artifact_digests(def, install_dir, events)?;
  load_module(engine, exec)
}
```

Hard rules (each closes a way the old bypass could creep back):
- **RO-rootfs only.** `locate_rootfs_aot` resolves *only* under the module install dir in `/usr/lib/hookprobe/modules/<id>/` (RO rootfs), canonicalized (symlink-free, non-traversal, must stay within the install dir — same guard as Fix B). It **never** looks at `DEVICE_CWASM_CACHE` (`/var/...`). The writable cache is dead for signed modules, permanently.
- **Read-once-verify-then-`deserialize`, never `deserialize_file`.** The bytes that are digest-checked are the exact bytes handed to `Module::deserialize`. No path is re-opened between check and load (kills TOCTOU by construction, as Fix A did for the `.wasm`).
- **Any doubt → verified JIT, never unauthenticated AOT.** Absent blob, arch-mismatch, digest-mismatch, or a `deserialize` `Err` (Wasmtime version/config drift, corruption) → fall to (3), the ADR 0016 floor. There is **no** code path from a failed AOT check to running the `.cwasm` anyway. This is the load-bearing safety property.
- **Digest-mismatch is an incident, not a warning.** A `role: aot` digest mismatch on a blob that *is* present emits an `ArtifactTamper` evidence event (ADR 0016 D2) before falling back — a swapped RO-rootfs blob is a tamper signal, surfaced in Detect/Investigate.

### D3 · Builder — precompile per arch, collect-then-sign, one signature over everything

The emulated-target `build` stage already produces the `.wasm`; add a precompile step and fold the AOT digests into signing.

1. **BUILD** — stage `build` compiles `<id>.wasm` (as today), then runs `hookprobe-supervisor --precompile <id> --precompile-out <staged-tree>/usr/lib/hookprobe/modules/<id>/` for each module. Because the stage runs as `${TARGETARCH}` with the Cargo.lock-pinned embedded Wasmtime, the emitted `<id>.cwasm` is native to the target arch and deserialize-compatible with the device. `gen-staging.sh` emits an `install` action placing it in the RO rootfs (mode `0644`) beside the `.wasm`. The `/var` `hookprobe-precompile.service` step is **no longer on the signed-module path**.
2. **DIGEST** — `--write-artifact-digests` learns `role: aot` entries: it computes each arch's `.cwasm` digest from the per-arch build output and writes it into `module.yaml` as a `role: aot, arch: <a>` entry. Because signing is one-shot over the whole module tree but `.cwasm` is per-arch, `sign-release.sh` **gathers every target arch's AOT digest first** (from each arch's staged tree) and only **then** signs — the collect-then-sign ordering. `.sig` still covers the final `module.yaml`.
3. **SIGN** — unchanged mechanism: `SHA-256(module.yaml)` → sign → `module.sig`. One signature now transitively covers the `.wasm` *and* every arch's `.cwasm`.

`verify-staging.sh` / `release-pass.sh` become **arch-aware**: the *current* arch's `role: aot` artifact (if declared) must be staged and its shipped bytes must match the signed digest (a reproducibility + tamper gate — re-verify the blob against the manifest post-sign); other-arch `aot` entries are metadata-only and must **not** trigger a "not staged" failure. A `signature: required` wasm module that ships **no** `aot` artifact for the built arch is a **warning, not a failure** — it simply falls back to verified JIT (safe, slow). The ADR 0016 executable-digest gate (D5, hard-fail) is untouched.

### D4 · First-boot precompile service — retired from the signed path, scoped to dev

`hookprobe-precompile.service` (writes `/var/lib/hookprobe/modules-cache`) is **removed from the default preset** for signed modules — their `.cwasm` now ships in the image, so there is nothing to precompile at first boot (and first-boot compile was itself a boot-time CPU tax on every OS upgrade). The unit is retained only as an **opt-in dev convenience for `signature: unsigned` local modules** (which never had ADR 0016/0017 protection and still use the `/var` fast path). Net effect: a shipped device does **zero** JIT/AOT compilation at first boot for its signed SOC — it deserializes ready-made native code.

### D5 · Independence from dm-verity (ADR 0006) — confirmed

Because the AOT blob's digest lives in the **signed** manifest, the guarantee holds **without** dm-verity, exactly as ADR 0016's `.wasm` guarantee does: a swapped RO-rootfs `.cwasm` fails the digest check and falls to verified JIT + emits `ArtifactTamper`. So ADR 0017 is **independently safe** and does **not** block on ADR 0006 landing. Verity remains recommended defense-in-depth (it makes the swap impossible at the block layer rather than merely detected at load), but is not a precondition. This preserves ADR 0016 D4's floor: artifact-hash signing protects even where verity is `none` (cloud/N100/VM today).

---

## Honest current state per platform (do not overclaim)

| Platform | RO `/usr` | dm-verity on `/usr` | TPM | ADR 0017 fast path | Notes |
|---|---|---|---|---|---|
| Pi 4 (arm64) | yes (bootc/composefs) | Pi path `verified`→`enforced` (ADR 0016 D4) | **absent** | works (A needs no TPM) | Approach B would have *no* hardware key here — a decisive reason to pick A |
| Pi 5 / RK3588 (arm64) | yes | `verified` (Pi anchor) | present | works | |
| N100 (amd64) | yes | **`none`** today | present | works | A holds without verity (D5); verity deferred to ADR 0006 |
| VM / cloud (amd64) | yes | **`none`** today | vTPM/absent varies | works | air-gapped/standalone default — offline manifest digest is the control |

RO `/usr` is immutable by construction on every bootc platform, but tamper-*evidence* is cryptographic only where verity is `enforced`; elsewhere the signed AOT digest (this ADR) is the control, not filesystem permissions.

---

## Files that will change

**Schema / types**
- `crates/hookprobe-manifest/src/module_def.rs` — add `ArtifactRole::Aot` (kebab `aot`); add `arch: Option<String>` to `ArtifactDigest`.
- `crates/hookprobe-manifest/src/module_sig.rs` — add `verify_aot_binding(def, arch, path, bytes, events)` (find the `role: aot` entry for `arch`, canonicalize+path-bind the file to the install dir, digest-verify the bytes, fail-closed + `ArtifactTamper` on mismatch). Reuse `resolve_artifact_path`/digest-alg switch from ADR 0016.
- `manifest/schema/` (module JSON schema, if present) — add `aot` to the role enum + optional `arch`.

**Supervisor**
- `supervisor/src/wasm_loader.rs` — `load_module_gated`: insert the verified-AOT fast path (D2 pseudocode) ahead of the `from_binary` fallback; add `locate_rootfs_aot` (RO `/usr/lib/hookprobe/modules/<id>/` only, never `DEVICE_CWASM_CACHE`); use `Module::deserialize` on verified in-memory bytes (never `deserialize_file`); keep the unsigned path exactly as Fix A left it. Add an arch accessor (from the manifest).
- `supervisor/src/main.rs` — `--write-artifact-digests` handles `role: aot, arch:` entries; ensure `--precompile`/`--precompile-out` can target a staged-tree module dir at build time (mechanism already exists — reuse, don't re-invent).

**Builder / release**
- `builder/gen-staging.sh` — emit an `install` action for `<id>.cwasm` (current arch) into `/usr/lib/hookprobe/modules/<id>/`, marked as the `role: aot` artifact for the built arch.
- `base/Containerfile` (stage `build`, Layer D2) — precompile each module's `.wasm` into the staged tree; update the "cwasm INTENTIONALLY NOT baked" comment (it now IS baked, per-arch, digest-in-signed-manifest); assert build-stage embedded Wasmtime == device (same Cargo.lock).
- `builder/sign-release.sh` — collect-then-sign: gather every target arch's `.cwasm` digest before the one `--sign-modules` step (D3).
- `builder/verify-staging.sh` (checks #5/#6) + `builder/release-pass.sh` — make the executing/AOT path-binding checks **arch-aware**: current-arch `aot` must be staged and byte-match the signed digest; other-arch `aot` entries are metadata-only; missing `aot` for the built arch is a warning (verified-JIT fallback), not a failure.
- `base/units/hookprobe-precompile.service` + `base/config/presets/` (and both `builder/mkosi*/mkosi.extra/...` copies) — drop from the default preset for signed modules; scope to unsigned dev opt-in.

**Modules (data)**
- `modules/*/module.yaml` — add `role: aot` artifact entries per built arch (populated by the builder, never hand-edited), for every `signature: required` wasm module (napse, qsecbit, dnsxai, aegis-guard, and any future wasm module).

**Docs**
- `docs/Readme.md` (supply-chain + cold-start) — the `~1–5 ms` cold start is restored via a **signature-covered** AOT blob, not a writable cache.
- `docs/adr/0009-soc-brain-edge-cloud.md` / `docs/adr/0016-artifact-hash-signing.md` — cross-reference: the Fix A regression is paid down here; the `.cwasm` moves inside the signed boundary.

---

## Alternatives considered

- **Approach B — device-key MAC over the writable `/var` `.cwasm`.** Keep first-boot precompile to `/var`, authenticate the bytes with a MAC under a TPM-sealed (or measured-boot-derived) key a `/var`-write attacker can't forge. **Rejected.** (1) **Pi 4 has no TPM** (project memory) — no hardware key root; a boot-derived key without measured boot is weak, so Pi 4 would fall back to A/JIT anyway, meaning we build A *and* B. (2) It keeps the trust root on the **writable** partition — the exact location error that caused the ADR 0016 bug — and depends on key lifecycle correctness rather than on the substrate being read-only. (3) It **still** pays a slow first-boot compile after **every** OS upgrade (new `.wasm` → recompile → re-MAC on device), whereas A ships ready-to-run native code in the image (zero first-boot compile). (4) Per-platform key divergence (TPM present/absent) violates "one OS, capabilities not branches." B is strictly more complex and strictly less aligned with a "detect once, RO substrate" system for no security gain over A.
- **Do nothing — accept the ~1000× Fix A regression.** Rejected: it abandons a stated product property ("~1–5 ms cold start"), taxes every boot/restart/upgrade on the most resource-constrained platform (Pi), and contradicts docs/Readme.md.
- **Cross-AOT with `Config::target(<triple>)` from a single-arch build host.** Unnecessary and was judged fragile-without-target-hardware in ADR 0009. Moot: the `build` stage already runs *as* the target arch (QEMU-emulated), so native precompile is free — no cross-target codegen path to validate.
- **Fold the `.cwasm` into a separate per-arch `.sig`.** Rejected for ADR 0016 D1's reason — multiplied trust surface + staging plan. Arch-qualified entries under the single existing signature achieve the same strength with one trust decision.

---

## Consequences

**Positive.** Restores ~2 ms cold start for the signed SOC *and* keeps the `.cwasm`-swap bypass closed — the native code that runs is now covered by the same signature as its `.wasm`. Zero first-boot compilation on shipped devices (the AOT blob ships ready). Extends ADR 0016's mechanism (same `module.sig`, same crypto-agility seam, ADR 0002) — no new signing primitive. A tampered RO-rootfs blob degrades to verified JIT and raises an evidence event rather than executing. Holds without dm-verity (D5), so it lands independently of ADR 0006. Retires a writable-partition trust surface and a boot-time CPU tax.

**Residual risks / costs.** (1) **Wasmtime version discipline is now load-bearing** — build-stage and device must share the exact embedded Wasmtime (they do, via one Cargo.lock; CI must *assert* it, and the `29.0.1` CLI drift in `base/Containerfile` must be reconciled — see Blocker). A drift silently degrades every load to JIT (safe, slow) rather than failing loudly; add a boot-time telemetry counter for "AOT fell back to JIT" so the regression is visible, not silent. (2) **`.cwasm` reproducibility** — the release-pass re-verifies the shipped blob against the signed digest; Wasmtime precompile is deterministic given fixed version+config, but CI must guard that (a compiler/flag bump changes the bytes → re-digest → re-sign). (3) **Image-size delta** — each image carries one arch's `.cwasm` per module (`.cwasm` is ~2–5× the `.wasm`); for ~10 few-hundred-KB modules this is low single-digit MB, acceptable, and bootc ships registry deltas. (4) **Builder ordering complexity** — collect-then-sign across the arch matrix (D3) is a real build-flow change; the payoff is one `.sig` per module (ADR 0015 preserved). (5) **Migration** — every signed wasm `module.yaml` gains `role: aot` entries in the landing release (builder-populated, like ADR 0016's `.wasm` digests); no grandfathering — a module either ships a verified AOT blob or falls back to verified JIT.

---

## Migration note — composition with ADR 0016 and ADR 0006

- **Extends ADR 0016, does not replace it.** The `.wasm` digest, the single `module.sig`, `verify_executable_binding`, and the Fix A verified-JIT floor all remain exactly as shipped. ADR 0017 adds one more artifact role under the *same* signature and one more (fail-closed, fall-back-to-the-floor) branch in `load_module_gated`. If ADR 0017's fast path is ever disabled, the system degrades precisely to ADR 0016 Fix A — safe, just slow.
- **Independent of ADR 0006 (verity).** Because the AOT digest is in the signed manifest, the control is cryptographic on every platform, verity or not (D5). ADR 0006 `enforced` verity is complementary (block-layer prevention vs. load-time detection) and remains recommended, but ADR 0017 needs neither it nor any specific ordering to be safe.

---

## Blocker found (report to release-engineer / verification-engineer)

**Wasmtime version drift between the two things that must match.** `supervisor/Cargo.toml` pins the *embedded* Wasmtime library — which both **produces** (`precompile_module`) and **consumes** (`deserialize`) every `.cwasm` — at `wasmtime = "27"` (`Cargo.lock`: `27.0.0`). `base/Containerfile` pins the *standalone CLI* `WASMTIME_VERSION=29.0.1`. They do not interoperate on AOT blobs (only the embedded lib touches them), so this is **not** a correctness bug for Approach A *today* — the build-stage supervisor and device supervisor share the one Cargo.lock and therefore match by construction. But it is a latent trap: (a) the drift invites someone to "fix" the mismatch by bumping the embedded lib on one side only, which would make every device `deserialize` fail and silently fall to JIT; (b) there is currently **no CI assertion** that the build-stage embedded Wasmtime equals the device embedded Wasmtime. **Required before A ships:** reconcile the `29.0.1` CLI pin (align it to the embedded `27.x`, or document explicitly that the CLI is unrelated to the AOT path), and add a CI gate asserting the build-stage and device supervisor are built from the same `Cargo.lock` Wasmtime version, plus a boot-time "AOT→JIT fallback" counter so any future drift surfaces as telemetry instead of a silent 1000× regression.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The per-arch `.cwasm` AOT concept survives but is bound to Wasmtime (std-heavy) + a composefs RO rootfs. Under heqk it needs a Wasm runtime that runs on the microkernel and a heqk RO-image delivery for the AOT blob; the `.cwasm` path is itself the plausible bridge that avoids porting the full Wasmtime JIT. → **Phase M5**.
