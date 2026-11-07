# ADR 0047 — heqk replaces Linux on every platform; Mission Control is served by heqk on the device

**Status:** 🟢 **Ratified by operator (2026-10-09)**. The operator answered two questions in session: (1) the Linux replacement covers **every platform**, not CM5 only; (2) Mission Control (UI + API) is **served by heqk on the device**. The wording below was drafted for operator review. Every clause is tagged **[realized]**, **[partial]** or **[vision]** (the ADR 0043/0044 discipline).

**Supersedes:** ADR 0044 **D2** (CM5-only scope). **Resolves:** ADR 0044 **D3** (app tier: B1 vs B2) in favour of the on-device UI/API. **Supersedes the tier split** in ADR 0043 and the CLAUDE.md line that bootc/Debian is "canonical + permanent" on UEFI/amd64/N100/cloud.

## Context

ADR 0044 made zero-Linux the target on CM5 and left two things open: the other platforms (kept on the bootc/Debian Linux tier as "canonical + permanent"), and where Mission Control runs (B1 native-on-heqk vs B2 off-device, B2 recommended). Following B2 put the operator-facing half of the product (evidence graph, API, UI) on a Linux-hosted stack. It also broke a core invariant on CM5: *standalone by default — a full local SOC, no account, air-gapped*. An air-gapped B2 sensor has no local operator view.

## Decision

### D1 · heqk is the operating system on every platform **[vision → partial on QEMU-aarch64 + CM5]**
HookProbe OS = the heqk capability microkernel plus software purpose-built around it, on QEMU/VM, CM5, RK3588, N100/x86_64 and cloud alike. No platform keeps Linux as its product substrate. Today heqk boots QEMU virt (aarch64) and CM5. Every other platform needs a port; the order and its real size are in `docs/design/heqk-everywhere-report-2026-10-09.md`.

### D2 · Mission Control is served by heqk, on the device **[partial: this ADR's E2E milestone]**
The device answers the operator directly: heqk serves the evidence/status API and the static Mission Control UI over its own TCP stack, on the IPS-gated datapath (`packet::verdict` both ways). Browser → device, no Linux in the path. This restores *standalone by default* on every heqk device. Fleet/MSSP aggregation is **additive**: the M6 export stream (ADR 0044 D3 B2 work, `exportwire.rs`) stays as the fleet feed, and the fleet aggregator is itself a heqk target (not a Linux service) once it exists.

### D3 · Linux's remaining role: build host and transitional image only **[realized: this clause]**
- Linux remains acceptable as a **developer/build host** (cargo, signing, QEMU, the host-side test sims such as `onboarding/enrollment/responder-sim`), because it is not shipped.
- The bootc/Debian images keep shipping **only until** each platform's heqk port passes its metal gate. Linux-tier code gets **bug and security fixes only, no new features**. New product capability lands in heqk.
- Linux-tier components are classified KEEP (portable logic / host tooling), PORT (re-host on heqk), REPLACED (heqk already supersedes) or RETIRE in the report. `retirement-agent` owns the retire list.

### D4 · Honesty floor **[realized: this clause]**
No external claim of "zero-Linux HookProbe OS" on a platform until heqk passes that platform's metal gate under a reproducible test. The x86_64 port (new arch crate, UEFI boot, drivers) is multi-month work and is stated as such.

## Consequences
- CLAUDE.md decisions #1/#2 (Containerfile/bootc, Wasm+Podman/Quadlet) describe the **transitional** Linux tier. heqk's equivalents are signed images with A/B tryboot (`hboot`) and the on-device Wasm host (`wasmhost` / `el0-wasmhost`).
- The `hookprobe-api` (Axum) contract becomes the **interface spec** the on-device server implements, so the existing UI works unchanged against a device.
- The e2e gap plan (`docs/design/e2e-gap-audit-2026-10-08.md`) drops its "Stage 3: Linux-tier wiring" in favour of the on-device Mission Control path.
