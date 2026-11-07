# ADR 0021 — Multi-arch native-artifact digests: generalize `role: aot`'s arch qualifier to `executable`/`loader`/`bpf-object`

**Status:** ✅ Accepted (2026-07-05) — implemented + verified green (485 workspace tests,
`--features wasm`, debug + release; 0 clippy errors, ≤ 36-warning baseline). Closes the
"native-binary digest gap" flagged by the on-Pi boot + release-engineer: a correct arm64 image
could not ship because `napse-quarantine`/`evidence`/`api`/`host-telemetry`'s payload digests were
pinned to a single (amd64-canonical) arch. **Extended same-day** to `napse-capture`'s `napse-dpi`
(flagged as an explicit follow-up when this ADR first landed; closed a few hours later, same
mechanism, no new code) after a full registry sweep confirmed it was the ONLY remaining native
binary with a single-arch-canonical digest — see the "Registry sweep" section below.
**Deciders:** code-developer (author, this pass), os-architect (to formalize/ratify),
release-engineer, verification-engineer.
**Relates to:** [ADR 0016](0016-artifact-hash-signing.md) (artifact-hash signing — the
`artifacts:` block, `verify_artifact_digests`, `verify_executable_binding` this ADR extends
without replacing), [ADR 0017](0017-authenticated-aot-cache.md) (the `role: aot`,
arch-qualified-`ArtifactDigest` mechanism this ADR generalizes to every native role — `arch:
Option<String>` already existed on `ArtifactDigest` since this ADR; the gap was that only `role:
aot` consulted it), [ADR 0002](0002-crypto-agility-pqc.md) (digest alg remains named/policy,
untouched here), [ADR 0015](0015-registry-driven-module-inclusion.md) (registry-driven staging;
the `staging.artifacts[].src -> dest` convention this ADR's builder wiring reuses unchanged).

---

## Context — the gap

ADR 0017 gave `ArtifactDigest` an `arch: Option<String>` field and made the supervisor
arch-selective for `role: aot` (`verify_aot_binding` picks the ONE entry whose `arch` matches
`module_sig::running_arch()`, ignores every other arch's entry as inert signed metadata). The
schema was generic from day one — nothing in `ArtifactDigest` restricted `arch` to `role: aot` —
but the VERIFICATION code (`verify_artifact_digests`, `verify_executable_binding`) never looked at
`arch` for any other role, and the BUILDER (`--write-artifact-digests`) only ever wrote arch-
qualified entries for `role: aot`.

The consequence, found by an on-Pi boot attempt: `napse-quarantine` (the loader ELF + `.bpf.o`),
`evidence`, `api`, and `host-telemetry` (the loader ELF) are **native binaries** — genuinely
different bytes per target arch (a Rust binary compiled for `x86_64` vs `aarch64` is a different
file, full stop). Their `module.yaml`s pinned exactly ONE digest, hand-annotated "pinned to the
AMD64 build," with a comment flagging the gap at every site. On an arm64 (Pi) image, the REAL
arm64 bytes of these binaries do not match that amd64 digest → `verify_artifact_digests`/
`verify_executable_binding` refuse fail-closed → the native eBPF loaders, the evidence graph, and
the Mission Control read-API all fail to start on the Pi. The schema (`arch` field) already
supported the fix; the gap was purely in the verification/builder code never using it outside
`role: aot`.

---

## Decision

Generalize the exact `role: aot` mechanism (ADR 0017) to `role: executable`/`loader`/`bpf-object`.
No new schema field — `ArtifactDigest.arch: Option<String>` already covers every role.

### D1 · Verification — arch-selective for every role, not just `aot`

- **`module_sig::verify_artifact_digests`** (`crates/hookprobe-manifest/src/module_sig.rs`): an
  artifact entry whose `arch` is `Some(_)` and does not case-insensitively equal
  `module_sig::running_arch()` is now **skipped entirely** — never opened, never hashed, never a
  reason to fail (mirrors `verify_aot_binding`'s existing rule, generalized to every role). An
  entry with `arch: None` remains arch-independent, exactly the pre-ADR-0021 behavior (zero
  regression for every already-shipped single-arch-canonical module).
- **D5 extension.** The existing "signature: required + empty `artifacts:` block is a hard-fail-
  in-release/warn-in-dev" rule (ADR 0016 D5) is extended: if a module declares a native role
  (`executable`/`loader`/`bpf-object`) **at all**, but **every** entry for that role is
  arch-qualified to some OTHER arch than this build's own, the module is exactly as unprotected on
  THIS arch as if it declared nothing — same hard-fail-in-release/warn-in-dev gate fires (new
  helper `role_declared_but_not_for_this_arch`). This is deliberately **not** treated like
  `role: aot`'s "absent AOT falls back to verified JIT, safe" case — a native binary has no JIT
  floor to fall back to; "wrong arch only" must refuse to load, not silently degrade.
- **`module_sig::verify_executable_binding`**: identical arch-skip inside its per-artifact loop
  (an entry `arch:`-qualified to a different arch never participates in the Finding-3 path-binding
  check, even if it happens to declare the exact same `path` as the arch-matching entry — arch, not
  merely path, now disambiguates which entry can bind). The pre-existing "no artifact bound → hard
  refusal, in every build profile" check already closes the "only the wrong arch is pinned" case
  unconditionally (this was true before this ADR too — Finding 3 refuses regardless of debug/
  release), so the D5-style message above is belt-and-suspenders documentation of *why*, not the
  only enforcement path.
- `role: aot` is untouched: `verify_aot_binding` remains the (more lenient — absence/mismatch falls
  back to verified JIT, never a hard failure) arch-selective check ADR 0017 defined; this ADR does
  not change its semantics, only extends the SAME `arch` field's consultation to sibling roles.

### D2 · Builder — `--write-artifact-digests` writes per-arch digests for every role, not just `aot`

`supervisor/src/main.rs`'s `--write-artifact-digests` handler generalizes the arch-match/skip logic
that used to be `role: aot`-only:

- An entry with `arch: Some(other)` where `other != running_arch()` is left **untouched** (that
  arch's own run of this same tool populates it) — now true for every role, not only `aot`.
- An entry with `arch: None` on a native role is the (unchanged) single-arch-canonical convention —
  this build's own bytes are written regardless of `running_arch()`, exactly as before this ADR.
- `want_arch` (which disambiguates a repeated `path:` when writing the `value:` line back into
  `module.yaml`, via `module_sig::write_digest_value_matching`) is now simply "whatever this
  entry's own `arch:` field says" for **any** role, not gated behind an `is_aot` check.
- **Collect-then-sign, unchanged.** `builder/sign-release.sh`/`builder/refresh-aot.sh` already ran
  `--write-artifact-digests all` once per arch, per the ADR 0017 D3 collect-then-sign ordering
  (each arch's own run touches only its own arch's entries; the LAST arch's run is followed by the
  one `--sign-modules` step). That flow needed **zero changes** to support native roles — it was
  already generic over "whatever entries `module.yaml` declares," and now those entries include
  native arch-qualified ones too.

### D3 · Release gate — `--check-artifact-digests` (and the shell scripts that call it) become arch-aware for native roles

`supervisor/src/main.rs`'s `--check-artifact-digests` (the byte-level PASS/FAIL/PENDING gate
`builder/verify-staging.sh` check #5 and `builder/release-pass.sh`'s post-sign gate both delegate
to) is updated identically:

- The D5 "has an executing-payload (`executable`/`loader`) digest pinned at all" check now counts
  only entries that **apply to this gate's own arch** (arch-less, or `arch:`-matching) — a module
  that pins digests ONLY for a different arch is correctly reported as unprotected on the arch this
  gate is checking, not silently passed.
- The per-artifact loop skips (with a `not this gate's arch — skipping` note, not a failure) any
  entry `arch:`-qualified to a different arch — the SAME entry is checked by that arch's own run of
  this gate. `builder/verify-staging.sh`/`builder/release-pass.sh` needed **no shell changes** —
  they already call the one Rust `--check-artifact-digests` binary rather than re-implementing the
  check, so the arch-awareness is inherited automatically.
- `builder/gen-staging.sh`/`stage-apply.sh` needed **no changes** either — they operate on
  `staging.artifacts[].src -> dest` (a *different*, already-arch-aware-via-`{gnu_bin}`/`{bin}`
  placeholder mapping from ADR 0015), never on the digest `artifacts:` block's own `role`/`arch`
  fields. One on-device `dest` per module, whichever arch's image it ships in — module.yaml's
  digest block enumerating both arches under that one `dest` is exactly the layer this ADR closes.

### D4 · `bpf-object` payloads: arch-qualify only where the bytes actually vary

Not every native role's bytes vary by arch. `napse-quarantine`'s `quarantine.bpf.o` and
`host-telemetry`'s `execsnoop.bpf.o` are CO-RE eBPF bytecode (`clang -target bpf`, always emitting
the portable "bpf" ISA); the `-D__TARGET_ARCH_<arm64|x86>` flag their Makefiles pass only affects
`PT_REGS`/register-layout macros a program consults if it reads task registers. Neither program
does — `quarantine.bpf.c` operates on `__sk_buff`/`ethhdr`/`iphdr` (TC-bpf classifier, no register
access); `execsnoop.bpf.c` is a `sched_process_exec` tracepoint (its own args struct, not
`pt_regs`). **Verified empirically this pass**: rebuilding each `.bpf.c` with both
`-D__TARGET_ARCH_arm64` and `-D__TARGET_ARCH_x86` against the same `vmlinux.h` produces
byte-identical `.o` output. Consequently both modules' `bpf-object` entries are kept as a **single
arch-less entry** — the honest representation, not a gap — while the verification code fully
supports an arch-qualified `bpf-object` too (proven by its own regression test,
`bpf_object_role_is_also_arch_selective`) for the day a different module's `.bpf.o` genuinely does
depend on register layout (e.g. a kprobe reading `PT_REGS_PARM1`).

---

## Files changed

- `crates/hookprobe-manifest/src/module_sig.rs` — `verify_artifact_digests` (arch-skip loop +
  `role_declared_but_not_for_this_arch` D5 extension), `verify_executable_binding` (arch-skip
  loop + the same D5-style message), two new private helpers
  (`has_arch_applicable_artifact`, `role_declared_but_not_for_this_arch`). Regression tests: 9 new
  (`artifact_digest_tests::{right_arch_digest_verifies_when_two_arches_share_the_same_path,
  wrong_arch_entry_is_skipped_even_sharing_the_same_path,
  no_matching_arch_digest_fails_closed_like_an_empty_artifacts_block,
  arch_less_entry_still_verifies_regardless_of_running_arch, bpf_object_role_is_also_arch_selective}`,
  `executable_binding_tests::{right_arch_entry_verifies_when_two_arches_share_the_same_path,
  wrong_arch_entry_is_never_consulted_even_sharing_the_same_path,
  no_matching_arch_entry_fails_closed_in_every_build_profile,
  arch_less_entry_still_binds_regardless_of_running_arch}`). No change to `ArtifactDigest`/
  `ArtifactRole` (`crates/hookprobe-manifest/src/module_def.rs`) — the schema already supported
  this (ADR 0017).
- `supervisor/src/main.rs` — `--write-artifact-digests`'s arch match/skip generalized off the
  `is_aot`-only condition to any `arch:`-qualified entry; `want_arch` derivation simplified to
  "whatever this entry's own `arch:` says." `--check-artifact-digests`'s `has_executing` computation
  and per-artifact loop made arch-aware (skip a different-arch entry, count only this-arch-
  applicable entries toward "an executing payload is pinned at all").
- `modules/napse-quarantine/module.yaml`, `modules/host-telemetry/module.yaml`,
  `modules/evidence/module.yaml`, `modules/api/module.yaml` — the `executable`/`loader` entries
  are now TWO arch-qualified entries (`arch: amd64` / `arch: arm64`) each, real digests of a fresh
  cross-build for both arches (aarch64-unknown-linux-gnu via the exact-glibc-2.36 sysroot wrapper
  `modules/napse-quarantine/README.md` documents; x86_64-unknown-linux-gnu native). `bpf-object`
  entries (napse-quarantine's `quarantine.bpf.o`, host-telemetry's `execsnoop.bpf.o`) are
  unchanged, single arch-less entries — D4 above.
- `modules/napse-capture/module.yaml` — the SAME treatment, added the same day once the registry
  sweep found it (see "Registry sweep" below): `napse-dpi`'s `role: executable` entry is now two
  arch-qualified entries, real digests of a fresh `x86_64-unknown-linux-musl` /
  `aarch64-unknown-linux-musl` rebuild. No `bpf-object` entry exists for this module (none is
  staged — AF_PACKET only).
- `builder/sign-release.sh`, `builder/refresh-aot.sh`, `builder/verify-staging.sh`,
  `builder/gen-staging.sh` — **no code changes required**; each already either delegates to the
  now-arch-aware Rust binary (`verify-staging.sh`'s check #5, `release-pass.sh`'s post-sign gate)
  or operates on the separately-arch-aware `staging.artifacts[]` mapping (`gen-staging.sh`), so the
  fix composes for free. `sign-release.sh`'s collect-then-sign ordering (run `--write-artifact-
  digests all` once per arch, sign once at the end) is unchanged and is exactly what this ADR's
  builder generalization needed.

---

## Verification performed this pass

- `cargo test --workspace --features hookprobe-supervisor/wasm` (debug **and** release): 485
  passed, 0 failed (up from 476+; +9 new arch-selection regression tests).
- `cargo clippy --workspace --all-targets --features hookprobe-supervisor/wasm`: 0 errors, 36
  warnings (≤ the 36-warning baseline `builder/gate-ladder.sh` enforces — no new warnings).
- Rebuilt fresh, real binaries for BOTH arches (never fabricated): `napse-quarantine`
  (`--features bpf`), `hookprobe-evidence`, `hookprobe-api`, `hookprobe-execsnoop`
  (`--features bpf`) for `x86_64-unknown-linux-gnu` (native) and `aarch64-unknown-linux-gnu` (via
  the sysroot-pinned cross wrapper). Ran `hookprobe-supervisor --write-artifact-digests <id>` once
  per arch (the arm64 leg under `qemu-aarch64-static`, so `module_sig::running_arch()` correctly
  reports `arm64`) to populate real digests — confirmed idempotent by re-running each leg a second
  time and observing byte-identical output.
- `hookprobe-supervisor --check-artifact-digests all` under the **native amd64** supervisor:
  `hard_fail=false`, all 4 target modules PASS for their amd64 entry (the arm64 sibling entries
  correctly reported "not this gate's arch — skipping", not a failure).
- The **same** command run under `qemu-aarch64-static` against the arm64-built supervisor: all 4
  target modules (`napse-quarantine`, `evidence`, `api`, `host-telemetry`) PASS for their arm64
  entry (amd64 siblings correctly skipped).
- `builder/gate-ladder.sh --fast --gate1`: **ALL REQUESTED GATES PASSED** (clippy, debug tests,
  manifest tests, release tests, `verify-staging.sh`, the digest fixture, and the release-pass
  rehearsal) — the amd64 leg is unaffected by this change.

---

## Registry sweep — `napse-capture` closure (same day, hours later)

The arm64 `--check-artifact-digests` run above surfaced exactly ONE failure outside the four
modules this ADR originally targeted: `napse-capture`'s `napse-dpi` — the SAME gap (a native
binary, single arch-less digest pinned to the amd64 build), and a real blocker for the arm64 Pi
image: `napse-capture` provides the `flows`/`packets` feed the wasm `napse` detection module reads
(`docs/architecture/Readme.md`'s Senzorium/Observe pipeline) — a refusal here is a dead detection pipeline on
the Pi, not a cosmetic gap.

**Closed with the identical D1/D2/D3 mechanism, zero new code**: `modules/napse-capture/module.yaml`
now pins two arch-qualified entries (`arch: amd64` / `arch: arm64`) for `napse-dpi`, real sha256 of
fresh rebuilds — `x86_64-unknown-linux-musl` (native) and `aarch64-unknown-linux-musl`
(`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc`; `napse-dpi` is a
pure-static-musl Rust binary with no `libbpf`/C dependency in its default build, so the plain
glibc-hosted cross linker suffices — unlike the `gnu`-toolchain modules, no exact-glibc sysroot is
needed here). `napse-dpi` ships no `.bpf.o` at all (AF_PACKET only, per the module's own long-
standing note), so there was no bpf-object entry to arch-qualify or arch-independence-verify.

**A full registry sweep was run to confirm this was the LAST gap**, not just the next one found by
accident: every `modules/*/module.yaml` was scanned for `role: executable`/`loader`/`bpf-object`
entries with no `arch:` field. Every remaining arch-less native entry was confirmed genuinely
arch-independent, not another instance of the gap:

| Module | Path | Why arch-less is correct |
|---|---|---|
| `napse`/`qsecbit`/`dnsxai`/`aegis-guard` | `<id>.wasm` | Wasm bytecode is portable by construction (the *arch-specific* derivative, `<id>.cwasm`, is already `role: aot`, arch-qualified since ADR 0017) |
| `ovs` | `/usr/lib/hookprobe/ovs/ovs-bringup` | A Bash script (`file`: "Bourne-Again shell script, ... text executable") — text is interpreted, not compiled; identical bytes run on every arch |
| `senzorium-flow` | `/usr/lib/hookprobe/senzorium-flow-export.sh` | Same — a Bash script, confirmed via `file` |

No other module carried a single-arch-canonical NATIVE (compiled) binary digest after this sweep.
`napse-capture`'s digests were re-signed alongside the other four in the same `builder/sign-
release.sh` pass (both legs: `module.sig` Ed25519 + `module.mldsa.sig` ML-DSA-65). Re-verification
after the fix: arm64 `--check-artifact-digests all` → `hard_fail=false`, **15 PASS, 0 hard
failures** (up from the one flagged FAIL); a full arm64 reconcile under `qemu-aarch64-static`
against the real `manifest/fixtures/rpi4-live.profile.json` Pi 4 fixture shows **all 14 discovered
modules** `verified` (signature) and, of the 12 the Pi4 class grants capabilities for (the other 2,
`edge-ai-detector`/`inline-guard`, correctly `refused` for unrelated hardware-absence reasons —
no NPU, no inline-role interface), **all 12 `running`/`healthy`**, including `napse-capture` itself
(`provides=["flows","packets"]`). `cargo test --workspace --features hookprobe-supervisor/wasm`
stayed at 485 passed/0 failed (no test changes needed — the mechanism was already fully generic);
`cargo clippy --workspace --all-targets --features hookprobe-supervisor/wasm` stayed 0 errors, no
new warnings; `builder/gate-ladder.sh --fast --gate1` stayed fully green on amd64.

---

## Consequences

**Positive.** The arm64 (Pi) image's native eBPF loaders, evidence graph, and Mission Control
read-API can now ship with a real, byte-verified digest instead of an amd64-pinned one that would
fail-closed-refuse on first boot. The fix is a pure generalization of an already-accepted mechanism
(ADR 0017's `arch` field + arch-selective verification) — no new schema, no new trust primitive, no
change to the crypto-agility seam (ADR 0002). Every already-shipped single-arch-canonical
`module.yaml` (the wasm modules' `.wasm`/`.cwasm`, `ovs`, `senzorium-flow`) is completely
unaffected (arch-less entries are untouched).

**Residual risks / costs.** (1) **Two entries per native artifact, one per arch, doubles the line
count of an already-verbose `artifacts:` block** — acceptable (mirrors `role: aot`'s established
shape) but a third+ target arch (riscv64) would add a third entry per artifact; no different in
kind from what `role: aot` already committed to. (2) **Builder discipline is now load-bearing
across more roles**: forgetting to run `--write-artifact-digests` under BOTH arches before
`--sign-modules` leaves one arch's entry stale/`PENDING` — caught by `--check-artifact-digests`'s
PASS/FAIL/PENDING three-case gate (unchanged, already the enforcement mechanism), not a new risk
this ADR introduces. (3) The `bpf-object` "provably arch-independent, so kept single-entry" call
(D4) is a per-program empirical judgment, not a blanket rule — any FUTURE `.bpf.o` that reads
`PT_REGS` must be arch-qualified like the native roles, and reviewers should re-verify the
byte-identity claim if either program's C source ever starts reading task registers. (4) **A new
native (compiled) module added to the registry after this ADR must remember to arch-qualify its
digest from day one** — the registry sweep (above) is a one-time proof this pass closed every
EXISTING gap, not an automated, standing CI check; `builder/verify-staging.sh`'s check #5/#6 catch
a genuinely wrong/missing digest at build time regardless, but nothing today specifically flags "a
new native binary shipped with only one arch's digest" as its own distinct warning class — a
worthwhile follow-up gate, not implemented here.

---

## Amendment (2026-07-08) — D6 · the `cpu:` micro-tier qualifier for `role: aot` (A76 selection)

**Status:** ✅ Accepted, implemented + gate-green (workspace tests `--features wasm` debug + release;
0 clippy errors, ≤ 36-warning baseline; `builder/lint-units.sh` + `gate-ladder.sh --fast --gate1`
incl. `0.4-manifest`/`0.7-separation-matrix` green). Extends [ADR 0017](0017-authenticated-aot-cache.md)
(the `role: aot` authenticated cache) with a SECOND selection dimension, exactly as this ADR added
arch-selectivity to the native roles. **Deciders:** os-architect (author/ratify), code-developer,
release-engineer, verification-engineer.

### The gap this closes

`builder/refresh-aot.sh --with-a76` already GENERATED, SIGNED, and STAGED a per-microarch AOT blob
on rpi5/rk3588 images (`<id>.a76.cwasm`, a `-cpu cortex-a76`/LSE-atomics precompile) and the
`module.yaml` already declared it as `role: aot, arch: arm64, cpu: cortex-a76`. But `ArtifactDigest`
had **no `cpu` field** (serde silently DROPPED it), `wasm_loader::locate_rootfs_aot` hardcoded a
single `<id>.cwasm` filename, and `module_sig::verify_aot_binding` selected by `arch` ALONE — so the
loader **never** selected the A76 blob. Every A76 device ran the A72-safe baseline; the signed A76
bytes were dead weight (the script's own header flagged this as blocked on "a `cpu`-tier selection
concept" that "does not exist" yet).

### D6 decision

1. **Schema.** `ArtifactDigest` gains `cpu: Option<String>` (`#[serde(default, skip_serializing_if)]`
   — additive, back-compat; an absent `cpu` = the arch's SAFE BASELINE). Meaningful for `role: aot`
   only. A single signed `module.yaml` may now enumerate, per arch, a baseline entry (no `cpu`) AND
   one-or-more `cpu:`-qualified faster tiers — `cpu`, alongside `arch`, disambiguates entries that
   legitimately repeat a role.
2. **Manifest is the source of truth for the tier.** The signed Platform Manifest gains
   `hardware.cpu.tier` (from `platforms/<profile>.yaml`'s new data-driven `cpu_tier` —
   `cortex-a76` for rpi5/rk3588, absent = baseline), frozen once at classification time
   (`PLATFORM_RULES_VERSION` bumped 2 → 3 so a fielded rpi5/rk3588 re-probes once to populate it).
   "Detect once, query forever": the loader READS the tier, never re-probes the CPU.
3. **Fail-closed tiered selection.** `wasm_loader::load_module_gated` tries candidate tiers
   MOST-SPECIFIC-FIRST — the manifest's `cpu_tier` (only ever ATTEMPTED when the signed manifest
   classifies the device as that tier), then ALWAYS the baseline. For each, `locate_rootfs_aot`
   reads the blob's filename straight from the matching signed `role: aot` entry (no hardcoded
   name), and `verify_aot_binding(arch, cpu, …)` digest-verifies the exact bytes against the entry
   matching BOTH `arch` AND `cpu` before `Module::deserialize`. **An A76 blob is loaded ONLY when
   the manifest says A76 AND its signed digest verifies; on absent/missing/tampered/deserialize-drift
   it falls to the baseline, then to verified JIT — never an A76 blob on an A72 (which would trap on
   an illegal LSE instruction), never a JIT crash.** A tampered `cpu:`-qualified blob still emits
   `ArtifactTamper` (incident), an absent one does not (normal).
4. **Builder unchanged in mechanism.** `write_digest_value_matching(path, Some(arch), …)` already
   disambiguates repeated-`path` `aot` entries by arch; the distinct A76 filename (`<id>.a76.cwasm`
   vs `<id>.cwasm`) means `cpu`-qualified entries are additionally distinguished by `path`, so no
   new builder-side matching was required.

### Residual risks

- **Tampered manifest on a same-arch device.** The `--run-wasm` streaming path reads
  `hardware.cpu.tier` best-effort (manifest-less otherwise). A manifest falsely upgrading an A72 to
  `cortex-a76` could make the loader attempt the legit-but-A76 blob, trapping on real A72 silicon —
  a **self-inflicted DoS, not RCE** (the blob bytes stay digest-bound to the SIGNED `module.yaml`,
  unforgeable), requiring write access to the persistent partition. Cross-ARCH is impossible (the
  `(arch, cpu)` joint match means an amd64/riscv box never even looks at an arm-tier entry).
  Mitigation: production verifies the manifest signature at provision time and freezes it; a future
  hardening is to signature-verify the manifest on the `--run-wasm` path too.
- **Per-tier blob proliferation.** Same shape/cost as this ADR's D-body arch proliferation — one
  more entry + one more staged blob per faster tier; bounded and opt-in (`--with-a76`).

---

## Amendment (2026-07-15) — D7 · the A76 tier is a *compute* tier: `+dotprod`/`+fp16` + the relaxed-SIMD determinism decision

**Status:** 🟡 Proposed (design only, no code — records the decision so the `dga-lm` build (ADR 0014)
and the base-tier framing (ADR 0031) have a ratified compute contract). **No speedup is asserted that
the verification gate below has not confirmed by disassembly.** **Deciders:** os-architect (author),
code-developer, verification-engineer (owns the disassembly + tick-cost gates), security-auditor
(determinism / reproducible-verdict invariant), telemetry-analyst (A76-SDOT vs A72-NEON measurement).
**Relates to:** [ADR 0017](0017-authenticated-aot-cache.md) (the AOT cache + `-cpu cortex-a76`
precompile this consumes), [ADR 0014](0014-continuous-improvement-detection-lifecycle.md) (the
`dga-lm` int8 classifier this unblocks on stock silicon), [ADR 0031](0031-dataplane-performance-strategy.md)
(the base-tier hardware framing that motivated this), [ADR 0009](0009-soc-brain-edge-cloud.md) (C9 —
why a *verdict* module may not be non-deterministic).

### The opportunity D6 left on the table

D6 selects a `cpu: cortex-a76` AOT blob (`<id>.a76.cwasm`, precompiled `-cpu cortex-a76`) from the
signed manifest — but today that tier's target-feature set is exploited only for **LSE atomics**. The
BCM2712 A76 (rpi5/cm5) and the RK3588 A76 are **ARMv8.2-A with FEAT_DotProd (SDOT/UDOT) and
FEAT_FP16** — the exact int8/fp16 primitives ADR 0014's `dga-lm` classifier was scoped to want. That
reframes ADR 0014's "int8-quantize because the A72 has no SDOT" note: on the A76 tier the SDOT path is
present on **stock silicon** — zero BOM, no WASI-NN backend, no NPU. This amendment makes the A76 AOT
tier a genuine **compute** tier, not only an atomics tier.

### D7 decision

1. **The `-cpu cortex-a76` precompile is treated as enabling `+dotprod +fp16`, not only LSE** — but as
   an **assertion to verify, not an assumption.** Because `builder/refresh-aot.sh` self-emulates
   `-cpu cortex-a76` under qemu, the feature view Cranelift sees is whatever that CPU model advertises
   via `HWCAP` (exactly the mechanism D6/ADR 0017 already rely on for LSE). The verification gate below
   is load-bearing; without it, no `+dotprod` claim ships.
2. **Relaxed-SIMD is opt-in and tier-scoped.** `Config::relaxed_simd(true)` is enabled ONLY for A76-tier
   modules that opt in; the A72 baseline keeps it off (or forced-deterministic) — the A72 has no SDOT
   and the int8 dot lowers to a NEON widening-multiply sequence there regardless.
3. **Determinism decision (the load-bearing call).** Relaxed-SIMD opcodes — notably
   `i32x4.relaxed_dot_i8x16_i7x16_add_s` — are **non-deterministic by the Wasm spec** (results may
   differ across engines/microarch). That collides with two invariants this repo depends on:
   reproducible signed-AOT and explainable/reproducible **verdicts** (C9, ADR 0009/0014). Therefore:
   - A module whose output is a **verdict** (feeds a detection/enforcement decision) **MUST NOT** use
     non-deterministic relaxed-SIMD. It uses either the deterministic base-SIMD dot
     (`i32x4.dot_i16x8_s`, i16) **or** relaxed-SIMD under Wasmtime's `relaxed_simd_deterministic(true)`
     (keeps the opcodes, forces a canonical lowering — may forgo the SDOT fast path). **Determinism
     wins over speed in the verdict path, always.**
   - A module whose output is **advisory-only** (a score surfaced to the operator / fed to QSECBIT, but
     never gating an inline decision — e.g. `dga-lm`, observe-only per C9) **MAY** use fast
     non-deterministic relaxed-SIMD, provided the score is documented engine/tier-dependent and never
     persisted as a reproducible training label without re-scoring off-device (ADR 0014 D4). Since
     `dga-lm` is observe-only, this is the expected path.
4. **No new schema field.** The `cpu: cortex-a76` qualifier (D6) already selects the tier; `+dotprod`/
   `+fp16` is a property of that tier's precompile, recorded in build provenance, not a `module.yaml`
   field. Every A76 in our fleet has FEAT_DotProd, so a finer "A76-without-dotprod" split is
   unnecessary.

### Verification gate (MUST pass before any `dga-lm`-on-SDOT perf claim)

Disassemble the signed `<id>.a76.cwasm` and confirm the int8 dot lowers to an actual **`SDOT`**
instruction. **If Cranelift emits a widening-multiply sequence instead, correctness and capability
gating still hold, but the "full SDOT throughput" claim is dropped until the lowering lands** — no
speedup asserted a benchmark hasn't shown (ADR 0031 discipline). telemetry-analyst records the A76
`dga-lm` tick cost vs the A72 NEON path.

### Residual risks

- **Cranelift-lowering dependency.** The SDOT win is contingent on Cranelift's aarch64 backend actually
  emitting SDOT for the (relaxed or base) dot op; a Wasmtime/Cranelift bump could change the lowering —
  pin the toolchain and **re-run the disassembly gate on every bump** (same discipline as the LSE
  feature pin in `refresh-aot.sh`).
- **Determinism footgun.** A global `relaxed_simd(true)` would silently make a *verdict* module
  non-deterministic. The gate ladder must reject a verdict-role module linking non-deterministic
  relaxed-SIMD without `relaxed_simd_deterministic` — a new lint (verification-engineer), **not
  implemented here.**
- **RK3588 big.LITTLE.** Its A76 cluster has FEAT_DotProd, but a detection tick may be scheduled onto an
  A55 core (also ARMv8.2+dotprod) — codegen is correct on both; the perf variance is a **scheduling**
  concern (ADR 0031 big.LITTLE pinning), not a codegen one.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL.** The arch-qualified + `cpu:` micro-tier digest/selection mechanism is substrate-independent Rust; only the artifact *targets* change (heqk ELF/`.cwasm`/BPF-object binaries). The A76 selection tier applies directly to the CM5 heqk build. → **Phase M5**.
