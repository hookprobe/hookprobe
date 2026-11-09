# Contributing to HookProbe OS

HookProbe OS is **one operating system** — a single signed OCI image, one data model, one evidence
graph, one AI. Every named component is a *module/lens* on the same substrate, never a separate
product. Before contributing, read ADR 0047 (`docs/adr/0047-heqk-everywhere-on-device-mission-control.md`:
heqk replaces Linux everywhere), `os/kernel/ARCHITECTURE.md` and `docs/architecture/MissionControl.md`
(the target dashboard); `docs/architecture/Readme.md` describes the legacy Linux tier, and skim `CLAUDE.md` for the load-bearing decisions that are not up for
relitigation.

## Ground rules

- **Capability-gate, don't hardware-branch.** Code asks "is `wifi7`/`openvswitch`/`edge_ai`
  granted?", never "is this a Pi?". The signed Platform Manifest is the single source of truth.
- **`runtime: wasm`** for detection/policy/enrichment; `container` only for heavy stateful
  services; `sysext`/image-layer for host-integral pieces.
- **Trust nothing unsigned.** heqk images are hybrid Ed25519 + SLH-DSA signed (`os/build/heqk-sign`);
  every image carries a CBOM; crypto choices are policy, not hardcoded.
- **Never gate the device on an account.** Cloud/account features are additive.
- **Observe by default; enforce only genuine, high-confidence attacks.** A legitimate customer
  connection must always pass. See the enforcement-separation ADR and the `0.7-separation-matrix`
  gate.
- **AI proposes, deterministic gates enforce** (contract C9). The AI planner is assistive and
  never in the enforcement path.

## The gates

Every change must pass the heqk gates before it can ship: **`os/kernel/validate.sh`** (builds heqk,
boots it under QEMU and checks every implemented phase gate by its PASS marker) and
**`os/kernel/tools/mc-e2e.sh`** (Mission Control API + browser end-to-end against heqk). Run both
locally before proposing a change; hardware-only behaviour is then proven on CM5 metal.

*(Legacy Linux tier only — `legacy/linux-tier/`: `builder/gate-ladder.sh --fast --gate1` remains the
gate for bug/security fixes there. The Rust/BPF bullets below date from that tier and still apply to
`legacy/linux-tier/` changes.)*

- **Rust:** `cargo test` + `cargo clippy` clean (no new warnings above baseline); `#![forbid(unsafe_code)]`
  is respected where set.
- **BPF:** if you touch a `.bpf.c`, recompile with `make bpf` and re-sign the module (build → digest
  → sign order — the `1.4-release-pass-rehearsal` gate catches inversions).
- **New enforcement/drop points:** add both a "legit passes" and an "attack still caught" row to the
  separation matrix.

## Change classes (governance)

- **Green** — docs/analysis. Propose freely.
- **Amber** — code, ADRs, roadmap, new marketing claims. Needs review; substantive architectural or
  posture changes need an **ADR** under `docs/adr/`.
- **Red** — commits to a release, flashing hardware, signing keys. Never automated.

## Security

Do **not** file security vulnerabilities as public issues — follow [`SECURITY.md`](SECURITY.md)
(coordinated, confidentiality-first disclosure).
