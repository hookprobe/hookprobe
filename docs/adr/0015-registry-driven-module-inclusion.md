# ADR 0015 — Registry-driven module inclusion + the one-file-to-add-a-module invariant

**Status:** ✅ Accepted (2026-07-04) — implemented: `builder/gen-staging.sh` (generator) → `builder/generated/staging-plan.json` + `85-hookprobe-modules.preset`, `builder/stage-apply.sh` (applier), `builder/verify-staging.sh` (gate). Proposed 2026-07-03.
**Deciders:** operator, os-architect, release-engineer, verification-engineer, code-developer.
**Relates to:** [ADR 0003](0003-platform-manifest-schema.md) (module model; `runtime ∈ wasm/container/sysext/image-layer`; capability gating), [ADR 0009](0009-soc-brain-edge-cloud.md) (`--run-wasm` verify-before-run, native sysext siblings napse-capture/napse-quarantine), [ADR 0002](0002-crypto-agility-pqc.md) (`signature: required`, device verifies never signs), [ADR 0012](0012-release-definition-cortex-pass.md) (what a release *is* — this closes a completeness hole in it). Mirrors the platform invariant in `docs/Readme.md` ("adding future hardware = one file in `platforms/`").

---

## Context — the disease a build-completeness audit found

HookProbe OS ships from **three hand-maintained inclusion lists, none derived from `modules/*/module.yaml`**:

1. `base/Containerfile` — the **bootc** image (cloud / N100 / edge-pro / VM).
2. `builder/mkosi-arm64/build-arm64.sh` — the **Pi / arm64** image.
3. `builder/mkosi/build-vm.sh` — the **amd64 VM** image.

Because each hard-codes *which* modules it stages, they drifted apart. The audit confirmed two failure classes:

**(a) Orphaned modules.** Registry-complete modules (`module.yaml` + `module.sig` present) that no build path stages: `napse-quarantine`, the `napse-capture` sysext/loader, `hydra`. Two more are staged by `build-arm64.sh` but have **no `module.yaml` at all**, so they are invisible to the registry: `host-telemetry` (staged from `modules/host-telemetry/` with no manifest) and `hookprobe-evidence` (lives under `crates/`, not `modules/`).

**(b) A hollow bootc SOC — the load-bearing bug.** `base/config/presets/80-hookprobe.preset` **enables** `senzorium-flow.service`, `napse-dpi.service`, `host-telemetry.service`, `hookprobe-retention.timer`, `hookprobe-evidence.timer`, and `napse-quarantine.service` — units the **Containerfile never installs**. `build-vm.sh` is worse: it copies the preset and the base binaries but **none** of the native-services units or wasm modules. systemd silently no-ops `enable` for a unit file that does not exist, so **cloud / N100 / edge-pro / VM images boot blind**: no software flow capture, no DPI, no host telemetry, no quarantine, no evidence graph, no retention cap. Only the arm64 / Pi path — which stages everything by hand — actually boots a full SOC.

The root cause is not any one missing `COPY`; it is that **inclusion is authored three times, by hand, and none of the three reads the registry.** The fix is to make `modules/*/module.yaml` the single source of truth for inclusion, exactly as `platforms/*.yaml` is the single source of truth for hardware, and to derive both build paths and one verification gate from it.

> **Scope note (concurrency):** a release-engineer bake is concurrently editing `build-arm64.sh` and `80-hookprobe.preset`. This ADR **specifies** the design against the *structure* of those files; it does not edit them. The plug-points below are described by role ("the wasm-staging loop", "the module-enable block of the preset"), not by line number, so they survive the bake.

---

## Decision

### D0 · The registry is the only inclusion list

`modules/*/module.yaml` is the **sole** declaration of what ships. A file is staged into an image **if and only if** it has a `module.yaml`. Two consequences, both enforced by the gate in D3:

- **Every staged artifact must have a `module.yaml`.** `host-telemetry` and `hookprobe-evidence` must gain one (see *Contradictions*, C2/C3). Nothing reaches an image outside the registry.
- **Every `module.yaml` is staged where it is capable.** No module may be silently dropped; a module that a target cannot run is *staged and supervisor-gated with a recorded reason*, never omitted.

### D1 · One generator, one artifact, two consumers

Add a **staging-manifest generator** that enumerates `modules/*/module.yaml` and emits **one** artifact — a **staging plan** — consumed by *both* build paths and by the Containerfile build stage. Nothing hand-lists modules again.

```
modules/*/module.yaml ──► builder/gen-staging.sh ──► builder/generated/staging-plan.json
                                                 └──► builder/generated/85-hookprobe-modules.preset
                                                            │
                        ┌───────────────────────────────────┼───────────────────────────────┐
                        ▼                                    ▼                                ▼
             build-arm64.sh (arm64)              build-vm.sh (amd64)          base/Containerfile stage `build`
                        └────────────── all call builder/stage-apply.sh <plan> <DEST> ────────┘
```

- **`builder/gen-staging.sh`** — the generator (bash + a Python heredoc, same shape as the existing `builder/gen-matrix.sh`; may later be re-homed as a small Rust bin `builder/staging-gen/` with no interface change). Inputs: `modules/*/module.yaml`, `--arch {arm64|amd64|riscv64}`, and optionally `--target platforms/<p>.yaml` (for the profile-aware validation pass, D5). Outputs the two generated files above. **This is the one place that reads YAML.**
- **`builder/stage-apply.sh <plan.json> <DEST_ROOT>`** — a thin, stable applier that executes the plan's actions (copy / install / symlink / preset-fragment). It parses **no YAML** — only the plan's JSON — so it is trivial and identical across all three callers. It resolves the path placeholders `{repo}`, `{wasm}`, `{bin}`, `{gnu_bin}`, `{dest}` from its arguments/env.

**Why a plan + applier, not one mega-script:** the plan is a reviewable, diff-able, CI-cacheable artifact (like `gen-matrix.sh`'s JSON). The applier is dumb and shared, so the three build paths converge on identical staging semantics. Adding a module changes only the *plan* (auto-generated); no build script changes.

#### The `module.yaml` staging block (schema addition)

The generator derives staging actions **by `runtime`** with conventional defaults, and reads an **optional `staging:` block** for the irregular cases (sysext loaders in `loader/`, host modules with a native binary, `.bpf.o` objects, sysctl drop-ins). Conventions (no `staging:` block needed) for the common wasm case:

| `runtime` | staged artifacts (convention) | dest | preset default |
|---|---|---|---|
| `wasm` | `{wasm}/<id>.wasm`, `modules/<id>/module.yaml`, `modules/<id>/module.sig`, `modules/<id>/units/*` | `/usr/lib/hookprobe/modules/<id>/` + units to `/usr/lib/systemd/system/` | `enable` each unit **unless hardware-gated** (D4) |
| `sysext` | loader bin `{bin|gnu_bin}/<loader>` → `/usr/lib/hookprobe/bin/`, `.bpf.o` → `/usr/lib/hookprobe/bpf/`, units → `/usr/lib/systemd/system/` | as listed | `enable` unless hardware-gated |
| `host` | `modules/<id>/*.sh` → `/usr/lib/hookprobe/`, optional bin, units, sysctl → `/usr/lib/sysctl.d/` | as listed | `enable` |
| `image-layer` | `modules/<id>/config/*` → `/usr/lib/hookprobe/<id>/`, units → `/usr/lib/systemd/system/` | as listed | per module (`ovs` = **disable**, supervisor starts on demand) |
| `container` | quadlet `*.container`/`*.volume` → `/usr/share/containers/systemd/` | as listed | quadlet-managed |

Explicit override block (used by `napse-capture`, `napse-quarantine`, `senzorium-flow`, `host-telemetry`, `hookprobe-evidence`):

```yaml
# appended to module.yaml — declares concrete artifacts when they deviate from convention
staging:
  build:                                   # cargo crates the build stage must compile for this arch
    - crate: napse-quarantine
      features: [bpf]
      toolchain: gnu                       # gnu | musl | wasm  → picks {gnu_bin}/{bin}/{wasm}
  artifacts:
    - { src: "{gnu_bin}/napse-quarantine", dest: "/usr/lib/hookprobe/bin/napse-quarantine", mode: "0755" }
    - { src: "modules/napse-quarantine/sysext/usr/lib/hookprobe/bpf/quarantine.bpf.o",
        dest: "/usr/lib/hookprobe/bpf/quarantine.bpf.o", mode: "0644" }
  units:
    - "modules/napse-quarantine/sysext/usr/lib/systemd/system/napse-quarantine.service"
  preset: { napse-quarantine.service: managed }   # enable | disable | managed (see D4)
```

#### The staging plan (the one generated artifact)

`builder/generated/staging-plan.json`:

```json
{
  "schema": 1,
  "arch": "arm64",
  "target_profile": null,
  "build_targets": [
    { "crate": "napse", "toolchain": "wasm" },
    { "crate": "napse-loader", "bin": "napse-dpi", "toolchain": "musl" },
    { "crate": "napse-quarantine", "toolchain": "gnu", "features": ["bpf"] },
    { "crate": "hookprobe-evidence", "toolchain": "gnu" },
    { "crate": "hookprobe-execsnoop", "toolchain": "gnu", "features": ["bpf"] }
  ],
  "modules": [
    {
      "id": "napse", "runtime": "wasm", "signature": "required",
      "gate": null,
      "actions": [
        { "op": "install", "src": "{wasm}/napse.wasm", "dest": "/usr/lib/hookprobe/modules/napse/napse.wasm", "mode": "0644" },
        { "op": "copy",    "src": "{repo}/modules/napse/module.yaml", "dest": "/usr/lib/hookprobe/modules/napse/module.yaml" },
        { "op": "copy",    "src": "{repo}/modules/napse/module.sig",  "dest": "/usr/lib/hookprobe/modules/napse/module.sig", "requires_sig": true },
        { "op": "copy",    "src": "{repo}/modules/napse/units/napse.service", "dest": "/usr/lib/systemd/system/napse.service" }
      ],
      "preset": [ { "unit": "napse.service", "verb": "enable" } ]
    },
    {
      "id": "napse-quarantine", "runtime": "sysext", "signature": "required",
      "gate": null,
      "actions": [ "...from staging.artifacts + staging.units..." ],
      "preset": [ { "unit": "napse-quarantine.service", "verb": "enable" } ]
    },
    {
      "id": "edge-ai-detector", "runtime": "wasm", "signature": "required",
      "gate": { "capability": "edge_ai", "reason": "requires an NPU with a ready driver + memory>=8192; supervisor enables at runtime when granted" },
      "actions": [ "...stage the .wasm + yaml + sig..." ],
      "preset": [ { "unit": "edge-ai-detector.service", "verb": "managed" } ]
    }
  ]
}
```

`build_targets` is the deduplicated set of cargo crates every staged module needs (drives the Containerfile build stage and the mkosi pre-build). `gate` is non-null for hardware-gated modules — the machine-checkable justification the D3 gate accepts in place of preset-enablement.

### D2 · Bootc parity falls out of D1 for free

`base/Containerfile` reaches arm64 parity by building the **native-services layer** and COPYing it — and because the *same plan* drives it, parity is structural, not a second hand-list.

**Stage `build`** (currently: two host bins + four wasm modules, hand-listed). Replace the hand-list with:

1. `COPY builder/generated/staging-plan.json /plan.json` (generated in CI *before* `podman build`, checked into `builder/generated/` or produced by a pre-build `make` step).
2. Compile every crate in `plan.build_targets` for its toolchain (`wasm32-wasip1` / `<arch>-unknown-linux-musl` / `<arch>-unknown-linux-gnu`). This adds the crates the bootc image is missing today: `napse-loader` (→ `napse-dpi`), `hookprobe-execsnoop`, `hookprobe-evidence`, `napse-quarantine`.
3. `RUN builder/stage-apply.sh /plan.json /out/tree {repo}=/src {wasm}=... {bin}=... {gnu_bin}=...` — assemble a copy-ready tree under `/out/tree`, plus copy the generated preset to `/out/85-hookprobe-modules.preset`.

**Stage `os`** (currently: ~12 hand `COPY --from=build` lines across Layer D2/F). Replace them with **two** lines:

```dockerfile
COPY --from=build /out/tree/                       /
COPY --from=build /out/85-hookprobe-modules.preset /usr/lib/systemd/system-preset/
RUN  systemctl preset-all || true
```

Everything that is *not* a registry artifact — `platforms/`, `manifest/schema/`, `base/units/`, `base/config/`, `base/greenboot/` — keeps its existing static `COPY`. The base preset (`80-hookprobe.preset`) keeps the **base-unit** enable lines (bootstrap, supervisor, mounts, measured-boot, network-reconcile); the **module** enable lines move to the generated `85-hookprobe-modules.preset` (see *Contradictions*, C4 — this touches the file the bake edits; coordinate).

Because `build-arm64.sh` and `build-vm.sh` call `stage-apply.sh` with the same plan, the arm64/amd64/bootc images now stage the **identical module set** for their arch. The arm64 path that "works today" and the bootc path that was "hollow" become the same code path.

### D3 · The verification gate — silent orphaning becomes a build error

Add `builder/verify-staging.sh`, invoked by `builder/smoketest.sh` (Gate 2, inside the built image) **and** standalone against the assembled staging tree (pre-build, in CI). It asserts, for the built image `$ROOT`:

1. **No orphaned registry entry.** For every `modules/*/module.yaml` with `signature: required`: either
   - its artifact **is staged** at the plan's `dest` **and** its `module.sig` is staged **and** cosign/`module_sig` verifies it against the baked trust store, **or**
   - the plan marks it `gate: { capability, reason }` with a **non-empty** reason (staged-but-supervisor-managed).
   Otherwise → **FAIL**: `orphan: <id> is signature:required but neither staged+signed nor capability-gated-with-a-reason`.
2. **No hollow preset (the disease, caught directly).** Every `enable <unit>` / `disable <unit>` line across `80-hookprobe.preset` + `85-hookprobe-modules.preset` must resolve to a unit file **actually present** under `/usr/lib/systemd/system/`. A preset line for a missing unit → **FAIL**: `hollow preset: enables <unit> which is not installed`.
3. **No staged artifact outside the registry.** Anything under `/usr/lib/hookprobe/modules/`, `/usr/lib/hookprobe/bin/`, `/usr/lib/hookprobe/bpf/` that does not trace back to a `module.yaml` action → **FAIL** (catches `host-telemetry`/`evidence` until they gain a `module.yaml`).
4. **Parity check.** The staged module set is identical (by id) across the arm64 and amd64 plans for a given profile, modulo arch-specific `.wasm` vs native artifacts. Divergence → **FAIL**.

An escape hatch for not-yet-buildable stubs must be **explicit**, never silent: a module may carry `status: stub` in its `module.yaml`, which exempts it from (1) but is surfaced in the build log and the validation matrix as "shipped: no (stub)". `edge-ai-detector`, `inline-guard`, `hydra` are `status: stub` today (BuildPlan Track-B: 🔲).

### D4 · Capability gating at build time — stage always, enable conditionally

A bootc image is byte-identical across every platform of the classes it serves (edge-pro runs on RK3588 **and** N100). So the generator **never omits** a module for capability reasons — it always stages the artifact. It decides only **preset enablement**:

- `requires.capabilities ⊆ the always-on baseline` (`soc`, `ids`, `capture`, `host_telemetry`, `dns_filtering` — all `policy: enabled` on the edge/cloud classes) → **`enable`** in the generated preset.
- `requires.capabilities` includes a **hardware-gated** token (`edge_ai`, `inline_ips`, or the XDP-drop `ddos_mitigation` path) → **`managed`**: stage the artifact, emit **no** preset-enable, and record the `gate.reason`. The **supervisor** enables/loads it at runtime when the manifest grants the token (exactly the existing pattern for `openvswitch-switch.service`, which the base preset already `disable`s and the supervisor starts on demand when `sdn` grants).

This is precisely "staged-but-preset-managed per the supervisor's existing gate, NOT silently dropped." The optional `--target platforms/<p>.yaml` pass additionally lets CI *downgrade* a preset line to `disable` where a class denies the capability by policy (e.g. `ovs` on `cloud`, whose `openvswitch: policy: disabled`), producing the tighter per-class expectation used by the D5 matrix — but the **default, profile-agnostic** plan stages everything and lets the supervisor gate, keeping the image universal.

### D5 · The one-file-to-add-a-module invariant

State it as the module analogue of the platform invariant:

> **Adding a module = one file in `modules/` — `modules/<id>/module.yaml` (+ its `module.sig`). No build-script, Containerfile, or preset edit.**

The design guarantees it: `gen-staging.sh` enumerates `modules/*/module.yaml` → the plan gains the new module → all three build paths stage it via the shared `stage-apply.sh` → the D3 gate fails the build if it was somehow dropped or left unsigned. A new `module.yaml` therefore **ships everywhere it is capable**, preset-enabled if baseline or supervisor-managed if hardware-gated, with **zero** edits to `Containerfile` / `build-arm64.sh` / `build-vm.sh` / the preset. The verify gate is what *guards* the invariant (adding a module without signing it, or a build path that quietly drops it, is now a hard error rather than a silent orphan).

---

## Implementation spec (for release-engineer / code-developer, once the bake frees the scripts)

**Files to add**

- `builder/gen-staging.sh` — generator (bash + Python heredoc; mirror `gen-matrix.sh`). Reads `modules/*/module.yaml`, `--arch`, optional `--target`. Emits `builder/generated/staging-plan.json` + `builder/generated/85-hookprobe-modules.preset`.
- `builder/stage-apply.sh` — applier. `stage-apply.sh <plan.json> <DEST_ROOT>` + placeholder env (`REPO=`, `WASM=`, `BIN=`, `GNU_BIN=`). Executes `install`/`copy`/`symlink` ops; `requires_sig` ops fail if the `.sig` is absent (dev: warn under `--relaxed`; CI: hard fail).
- `builder/verify-staging.sh` — the D3 gate. Runs against a built image root or the staging tree.
- `modules/host-telemetry/module.yaml` — **new registry entry** (`runtime: sysext`, `provides: [host_telemetry]`, `requires: [host_telemetry]` or `[soc]`; `staging:` block for `execsnoop.bpf.o` + `hookprobe-execsnoop` + `host-telemetry.service` + `hookprobe-retention.{service,timer}`; `signature: required`).
- `modules/evidence/module.yaml` — **new registry entry** for `hookprobe-evidence` (`runtime: host`, `requires: [soc]`, `provides: [evidence]`; `staging.build: [{crate: hookprobe-evidence, toolchain: gnu}]`; units from `crates/hookprobe-evidence/units/`; `signature: required`). Alternative: move the crate's units under `modules/evidence/`. **Flag, don't resolve** (C3).

**Files to change (after the bake merges)**

- `modules/*/module.yaml` — add the optional `staging:` block to the irregular modules (`napse-capture`, `napse-quarantine`, `senzorium-flow`, `host-telemetry`, `evidence`); add `status: stub` to `edge-ai-detector`, `inline-guard`, `hydra`.
- `base/Containerfile` — stage `build`: replace hand-listed cargo builds with the `plan.build_targets` loop + `stage-apply.sh` into `/out/tree`. Stage `os`: replace Layer D2/F module `COPY`s with the two-line parity COPY (D2).
- `base/config/presets/80-hookprobe.preset` — **move** the module-enable lines (`senzorium-flow`, `napse-dpi`, `napse`, `qsecbit`, `dnsxai`, `aegis-guard`, `host-telemetry`, `hookprobe-retention.timer`, `hookprobe-evidence.timer`, `napse-quarantine`, `hookprobe-scan-responder*`, `hookprobe-precompile`) into the generated `85-hookprobe-modules.preset`; keep base-unit lines. (Touches the bake's file — coordinate; C4.)
- `builder/mkosi-arm64/build-arm64.sh` + `builder/mkosi/build-vm.sh` — replace the per-module `install`/`cp` blocks with a single `source stage-apply.sh; stage_apply "$PLAN" "$EX"`. `build-vm.sh` gains the native-services + wasm staging it lacks entirely today (its hollow-SOC fix).
- `builder/smoketest.sh` — add a `## 6. staging completeness` section calling `verify-staging.sh` (fail the smoke run on any orphan / hollow-preset).
- `.github/workflows/build-os.yml` — run `gen-staging.sh --arch <matrix.arch>` before `podman build`; publish `staging-plan.json` as a build artifact for audit.

**Exact plug-points (structural, not line-numbered — robust to the concurrent bake)**

- *Containerfile stage `build`*: the block that does `cargo build ... -p napse -p qsecbit -p dnsxai -p aegis-guard` and the `cp ... /out/modules/`. Replace with the `build_targets` loop + `stage-apply.sh /out/tree`.
- *Containerfile stage `os`*: Layer **D2** (the four `COPY --from=build /out/modules/*.wasm` + the four `module.yaml`/`module.sig` COPYs) and the module-unit COPYs in Layer **F** (`modules/{napse,qsecbit,dnsxai,aegis-guard}/units/`). Replace both with `COPY --from=build /out/tree/ /` + the generated-preset COPY.
- *build-arm64.sh*: the `for eng in napse qsecbit dnsxai aegis-guard` wasm loop, the `senzorium-flow` / `napse-dpi` / `host-telemetry` / `hookprobe-evidence` / `napse-quarantine` install blocks. Replace all with the single `stage_apply` call.
- *build-vm.sh*: it has **no** module staging — insert the single `stage_apply` call after the base-binary install.
- *preset*: the block of `enable <module>.service` lines (D4/C4).

---

## Per-device validation matrix (D5 acceptance test)

For each platform, given its `platforms/<p>.yaml` capability policy, the **runtime** expectation the verification-engineer asserts per image. **Every module is STAGED on every image of the right arch** (universal image); the columns below are the *runtime* verdict the supervisor must reach from the signed manifest. `A` = active (capability granted, module loaded); `M` = staged, supervisor-managed, **off with a recorded reason** (correctly gated); `A?` = conditional (active iff the noted runtime fact holds); `stub` = `status: stub`, not shipped yet.

| Module (runtime) | Deciding capability | Pi 5 (`rpi5`, edge-pro) | CM5 (`rpi5`, edge-pro, 2×LAN) | RK3588 (`rk3588`, edge-pro) | N100 (`n100`, edge-pro) | VM (`virtual`→`cloud`/`generic`) | Cloud (`cloud`) |
|---|---|---|---|---|---|---|---|
| `napse` (wasm) | `soc`,`ids` | A | A | A | A | A | A |
| `qsecbit` (wasm) | `soc` | A | A | A | A | A | A |
| `dnsxai` (wasm) | `soc` (provides `dns_filtering`) | A | A | A | A | A | A |
| `aegis-guard` (wasm) | `soc` | A | A | A | A | A | A |
| `hydra` (wasm) | `soc` | stub | stub | stub | stub | stub | stub (**dest = Intelligence**, see C1) |
| `senzorium-flow` (host) | `soc` | A | A | A | A | A | A |
| `host-telemetry` (sysext†) | `host_telemetry` | A | A | A | A | A | A |
| `evidence` (host†) | `soc` | A | A | A | A | A | A |
| `napse-capture` (sysext) | `capture` (drop path +`ddos_mitigation`) | A | A | A | A | A (OOB; no drop) | A (OOB; no drop) |
| `napse-quarantine` (sysext) | `capture` | A | A | A | A | A? (inert — no edge LAN; C5) | A? (inert; C5) |
| `ovs` (image-layer) | `openvswitch` (≥2 ifaces) | A? (eth+Wi-Fi ⇒ 2) | A (2×LAN) | A (≥2 NIC) | A (4×2.5GbE) | M (1 NIC — `openvswitch` disabled) | M (1 NIC — disabled) |
| `edge-ai-detector` (wasm) | `soc`,`edge_ai` | M (no NPU) | M (no NPU) | A? (NPU+driver ∧ mem≥8GB) | M (no NPU) | M (disabled) | M (disabled) |
| `inline-guard` (wasm) | `soc`,`inline_ips` | M (bcmgenet unvalidated) | M (carrier NIC unvalidated) | M (present_unsafe) | A? (iface in inline role ∧ igc/ixgbe) | M (disabled) | M (disabled) |

† `host-telemetry` and `evidence` are staged today but lack a `module.yaml`; the matrix assumes C2/C3 land (they gain a registry entry). Until then the D3 gate flags them as "staged outside the registry".

**Generic fallback** (`platforms/generic.yaml`, baseline-only): `napse`/`qsecbit`/`dnsxai`/`aegis-guard`/`senzorium-flow`/`evidence` = **A** (`soc`/`ids` enabled); `host-telemetry`/`napse-capture`/`napse-quarantine`/`ovs`/`edge-ai-detector`/`inline-guard` = **M** (their tokens are `policy: disabled` on generic). This is the local-first floor: a full baseline SOC still runs; every hardware-unlocked extra is correctly gated off with a reason.

**How the verification-engineer uses it:** boot each image on (or emulate) each device, read the signed manifest, and assert `staged ∧ (preset-enabled ∨ supervisor-managed) ∧ runtime-verdict == matrix cell`. An `A` that is inactive, or an `M` with no recorded reason, or any module missing from the staged set, fails the per-image acceptance test. This is the concrete, capability-gated set that "validate each image for each device, step by step" resolves to.

---

## Contradictions surfaced (C1–C3 RESOLVED 2026-07-05; C4/C5 for product-steward)

- **C1 · `modules/hydra/module.yaml` was stale — ✅ RESOLVED (2026-07-05).** It previously declared HYDRA as *"Automation & Orchestration"* (Automate workspace), contradicting the project canon (`CLAUDE.md`, `docs/v2-reconciliation.md`) and HYDRA's own unit (`hydra-feedsync` = *"Threat Feed Sync"*), which place HYDRA in **Intelligence** (threat-intel/enrichment). Corrected in place: `modules/hydra/module.yaml:23` now reads `workspace: Intelligence` (`title: "HYDRA — Threat Intelligence & Enrichment"`), with a header note recording the pre-correction stale mapping. Registry-content bug, fixed at the source.
- **C2 · `host-telemetry` had no `module.yaml` — ✅ RESOLVED (2026-07-05).** It was staged by `build-arm64.sh` and preset-enabled yet invisible to the registry. `modules/host-telemetry/module.yaml` now exists, so it is registry-driven and no longer flagged by the D3 gate.
- **C3 · `hookprobe-evidence` lived under `crates/`, not `modules/` — ✅ RESOLVED (2026-07-05).** Resolved the same way as C2: `modules/evidence/module.yaml` now exists as the registry entry referencing the crate artifact.
- **C4 · The generated preset touches the bake's file.** Moving module-enable lines out of `80-hookprobe.preset` into `85-hookprobe-modules.preset` edits the same file the concurrent release-engineer bake is editing. Sequence after the bake merges; do not race it.
- **C5 · `napse-quarantine` is `capture`-gated, but `capture` is `enabled` on `cloud`.** On a cloud/VM box the module would load and attach TC-bpf to the single virtio NIC — capability-granted but operationally inert (no edge LAN to quarantine). Consider gating enforcement modules on an edge-role token (or `ddos_mitigation`) rather than bare `capture`. Registry-content refinement; flagged for os-architect + product-steward.

---

## Consequences

**Positive.** Inclusion authored once, in the registry. The hollow-bootc-SOC bug becomes structurally impossible (D3 #2). Bootc reaches arm64 parity for free (D2). Adding a module is one signed file (D5). Every image's module set is machine-verified against its manifest capabilities (matrix).

**Residual risks.** (1) The generator adds a YAML-parsing step to the build; keep it in **one** place (`gen-staging.sh`) so the applier stays dumb. (2) The `build_targets` list grows the bootc build stage's compile time (adds `napse-loader`, `execsnoop`, `evidence`, `napse-quarantine` cross-builds) — the previously-honest reason the Containerfile omitted the native layer; CI must have the cross-toolchains (already used by `build-arm64.sh`). (3) `status: stub` is an honest escape but must be reviewed each release so stubs do not accumulate silently — surface them in the release pass (ADR 0012). (4) C2/C3 are prerequisites: until `host-telemetry`/`evidence` gain a `module.yaml`, they remain hand-staged and the gate reports them.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The "`module.yaml` registry is the sole inclusion truth / one-file-to-add-a-module" invariant survives. The staging plan's three targets (Containerfile / systemd-presets / sysext) become heqk's image + module format. → **Phases M5/M6**.
