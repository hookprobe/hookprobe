# builder/ — one Containerfile → installable artifacts for every platform

This is the **image-build pipeline**: it turns the single signed bootc OS image
(`base/Containerfile`) into per-platform, flashable artifacts, driven entirely by
`base/profiles/*.yaml`. The OS is identical on every target — a profile only tunes
optional packages and **which disk formats to emit**; the device still self-detects
its hardware at first boot (`bootstrap` → signed Platform Manifest).

> **Design test:** adding a new platform = one `base/profiles/<x>.yaml` (+ its
> `platforms/<x>.yaml` for runtime classification). No change here, no UI/API change.

## Pipeline (per `profile, arch`)

```
1. sign-release.sh   → release-sign every module + emit the trust store   (OFF-device / HSM)
2. podman build      → the signed bootc OCI image (cosign)                 (base/Containerfile)
3. bootc-image-builder → .raw / .iso / .qcow2 / .ami                       (per bib.variants)
```

Artifacts land in `builder/out/`.

## Where each platform's recipe comes from

`base/profiles/<profile>.yaml` carries a `bib:` block, e.g. `cloud.yaml`:

```yaml
bib:
  variants:
    - { arch: x86_64,  types: ["raw", "ami"] }   # generic IaaS + AWS
    - { arch: aarch64, types: ["raw"] }          # Graviton
  filesystem:
    - { mountpoint: /,                    minsize: "10 GiB" }
    - { mountpoint: /var/lib/hookprobe,   label: hookprobe-data }   # immutable rootfs + data partition split
```

`build.sh` reads that and runs the matching builds. Typical targets:
`rpi5`/`edge-pro` → `.img.xz` (arm64), `n100`/`edge-pro` → `.iso` (amd64),
`cloud` → `.raw`/`.ami`, `virtual` → `.qcow2` (boot smoke-test).

## Running it

```bash
# Dry-run the plan ANYWHERE (no podman needed) — what would be built:
builder/build.sh --profile cloud --plan

# Real build (BUILD HOST ONLY — needs podman + bootc-image-builder + cosign):
COSIGN_KEY=cosign.key builder/build.sh --profile cloud
builder/build.sh --profile edge-pro --arch aarch64 --type raw

# Emit the CI image-build matrix from all profiles (GitHub Actions):
builder/gen-matrix.sh
```

## Release pass (`release-pass.sh`) — ADR 0012 D3

Assembles the `release.json` evidence bundle (schema 1: version, per-`profile,arch`
digests, channel, platforms, commits, gate-ladder results, the four Ring-1
attestations, SBOM/CBOM/provenance refs, release-notes pointer) that closes ADR
0011's "who emits `release_image`" question. **Two paths write the exact same
bundle shape:** the CI `promote` + `release-pass` jobs
(`.github/workflows/build-os.yml`, gated behind a reviewer-approved
`release-promotion` environment — the canonical path that ships) and this script
(the **local rehearsal/dry-run path** release-engineer runs by hand against a
dev-built digest).

```bash
# Runs anywhere (no podman/registry needed) — pure local evidence assembly:
builder/release-pass.sh \
  --version 2026.7 --channel stable \
  --digest edge-pro:arm64:sha256:<hex> --digest cloud:amd64:sha256:<hex> \
  --gate "workspace-tests:pass:174 tests" --gate "clippy:pass" \
  --platform rpi4 --platform n100 \
  --commit "<sha>:add ring-window enforcement" \
  --attest all \
  --out release.json
```

**The Amber gate (ADR 0011 D3):** the script ALWAYS prints the four Ring-1
attestation checklist items (`verification-engineer` / `security-auditor` /
`release-engineer` / `product-steward`) and **refuses to write `--out`** unless
every role is attested — `--attest all`, or the four individual `--attest <role>`
flags. This is a mechanical stand-in for "agents produce the pass, the operator
approves it"; it does not verify that a human actually reviewed anything, it only
enforces that the flag was explicitly passed. The real publish/tag/push/promote
action stays 🔴 Red and lives in CI's `promote` job, gated separately.

## Gate ladder (`gate-ladder.sh`) — the local/CI entrypoint (verification-engineer canon)

`gate-ladder.sh` is the ONE command that runs the gate ladder in dependency order,
fail-fast, with a PASS/FAIL/SKIP summary — wiring together gates that already exist
(`cargo test`/`clippy`, `verify-staging.sh`, `test-artifact-digest-gate.sh`,
`release-pass.sh`, `smoketest.sh`) rather than reimplementing any of them. It is the
exact same script CI runs (`.github/workflows/gate-ladder.yml`) — local and CI can't
silently diverge.

```bash
builder/gate-ladder.sh              # Gate 0 + Gate 1 (the normal dev-box run)
builder/gate-ladder.sh --fast       # Gate 0 only (fmt/clippy/test-debug/manifest/ui)
builder/gate-ladder.sh --full       # Gate 0 + Gate 1 + Gate 2 (podman permitting)
builder/gate-ladder.sh --gate0      # just one tier
builder/gate-ladder.sh --gate1
builder/gate-ladder.sh --gate2      # image build + smoketest.sh (needs podman; opt-in)
```

| Tier | What it guards | Runs when |
|---|---|---|
| **Gate 0** | `cargo fmt --check` (skip-with-reason if rustfmt isn't installed) · `cargo clippy --workspace --all-targets --features hookprobe-supervisor/wasm` (0 errors is the hard bar; warning COUNT must not exceed a recorded baseline — `CLIPPY_WARN_BASELINE`, default 36 via `--message-format=json`, NOT a blanket `-D warnings`, since this tree carries known-tolerated pre-existing warnings) · `cargo test --workspace --features hookprobe-supervisor/wasm` (debug, 393 tests) · `manifest/validate.py` (ADR 0003 fixtures) · `ui/` build (skip-with-reason if no npm) | every push/PR |
| **Gate 1** | `cargo test … --release` · `builder/gen-staging.sh` + `builder/verify-staging.sh` (ADR 0015 D3 — orphaned modules, hollow presets, ADR 0016/0017 artifact-digest + path-binding + AOT checks) · `builder/test-artifact-digest-gate.sh` (the 7-case ADR 0016/0017 fixture harness) · `builder/release-pass.sh` REHEARSAL (dummy digest, `--attest all`, throwaway `--out`) — exercises the real post-sign gate (signature re-verify + byte-level digest recompute) without needing a real release | PRs |
| **Gate 2** | `podman build -f base/Containerfile` + `builder/smoketest.sh` (boot self-provisioning chain: bootstrap→signed manifest→supervisor VERIFIED→reconcile→`network-apply --check`, plus the staging-completeness gate against the BUILT image's filesystem) | nightly / manual dispatch / `run-gate2` PR label — never implied by a plain push, since it needs privileged podman and real time |

**Honesty rule, mechanically enforced:** a gate whose tooling is absent in the current
environment (no `rustfmt` component, no `npm`, no `podman`) SKIPs with a printed reason
and does not count as a failure — but also never silently counts as a pass. Gate 2
specifically: podman ABSENT → clean SKIP; podman PRESENT but the build fails/times out
→ FAIL (never conflated). Fail-fast: the ladder stops at the first FAILing gate; the
summary table printed so far is never suppressed.

Env knobs: `ARCH` (gen-staging/verify-staging arch, default `amd64`), `CLIPPY_WARN_BASELINE`,
`IMAGE_TAG`/`GATE2_PODMAN_BUILD_ARGS`/`GATE2_BUILD_TIMEOUT` (Gate 2), `SKIP_ADR0016_GATE`
(forwarded to the release-pass rehearsal for a docs-only run with no built supervisor).

The **Wasmtime version-drift assertion** (ADR 0017 Blocker — Cargo.lock's embedded
`wasmtime` crate version vs `base/Containerfile`'s `WASMTIME_VERSION` ARG) runs as its
OWN standalone CI job (`wasmtime-drift` in `gate-ladder.yml`), independent of Gate 0/1/2,
so a drift is caught even on a change that never triggers an image build.

## Honest status / prerequisites

- **`build.sh --plan` runs anywhere** (validated on the dev box) — it parses the
  profile and prints the exact `podman build` + `bootc-image-builder` commands.
- **The real build needs a build host**: `podman` (rootful or rootless+privileged),
  the `quay.io/centos-bootc/bootc-image-builder` container, and `cosign`. This dev
  box has none of those, so the real build is **not** runnable here — by design.
- **Trust store must be baked.** `sign-release.sh` writes `builder/trust/release.pub`
  + `modules/*/module.sig`. The Containerfile already `COPY`s `modules/` (sigs ride
  along); add `COPY builder/trust/ /usr/share/hookprobe/trust/` and run the supervisor
  with `--trust /usr/share/hookprobe/trust`. Without this, "trust nothing unsigned"
  refuses every `signature: required` module — i.e. an image with no trust store runs
  nothing (intended secure posture).
- Signing keys are **off-device** (release HSM, ADR 0002); the device only verifies.
  `sign-release.sh` uses a deterministic DEV key as a stand-in.
- **`release-pass.sh` runs anywhere** (validated on the dev box, incl. the Amber-gate
  refusal path) — it does not need podman/cosign/a registry, only `python3`. It does
  NOT verify the digests it's given are real or that the gates actually ran — it
  trusts its arguments; the CI `promote`/`release-pass` jobs are what tie a
  `release.json` to digests this repo actually built and signed.

See `docs/OS-platform-report.md` (§6 sequence, §8.x validation),
`docs/adr/0012-release-definition-cortex-pass.md`, and `docs/BuildPlan.md`.
