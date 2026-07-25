# ADR 0044 — Zero-Linux on the rpi-native tier (CM5): heqk replaces Linux as substrate **and** app-host

**Status:** 🟢 **Ratified by operator (2026-07-25)** — the operator, presented with the A-vs-B fork below, chose **B (zero-Linux)** and directed Phase-0 alignment to begin. Amends/supersedes the **app-tier** half of [ADR 0043](0043-heqk-microkernel-substrate.md): specifically **D5.6** (the "monitored Linux *guest* VM for the app tier — heqk replaces Linux-as-substrate, not Linux-as-app-host" scoping) and the rejected-alternative framing that named a Linux-guest-app-host as "the bounded, reversible path." Every principle is tagged **[realized]** (true on metal), **[partial]**, or **[vision]** (design-only) — the same honesty discipline as ADR 0043, because on the app tier this ADR is almost entirely **[vision]** and overstating it is the one way it does harm.
**Deciders:** operator (ratification — **given**), os-architect (architecture), product-steward (this record + ADR 0043 reconciliation), release-engineer (CI/CD + variants), security-auditor (TCB/supply-chain), verification-engineer (gate ladder).
**Relates to:** [ADR 0043](0043-heqk-microkernel-substrate.md) (the substrate-replacement keystone this extends from substrate to app-host), [ADR 0041](0041-container-vm-overlay-management.md) (the overlay/VMM this **de-scopes for CM5**), [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D6/D8 (ownership + the reserved slice), [ADR 0009](0009-soc-brain-edge-cloud.md) (edge/cloud split — the app-tier off-device option leans on it), the Product-Cortex canon (`CLAUDE.md`, `docs/BuildPlan.md` Track C), `docs/MIGRATION-heqk.md` (whose M6 this rewrites). Companion decision records: ADR 0045 (default dev/test credentials), ADR 0046 (GitHub migration + git-history inheritance + key custody).

> **One-line thesis:** on the CM5/rpi-native tier, **no Linux runs on the device — not even a guest.** heqk provides the whole stack (boot, TCB, dataplane, detection, storage, the Wasm module host, Wi-Fi AP); the heavy app tier is either rebuilt native-on-heqk or moved *off-device* (hosted control plane). This is the maximal expression of "the OS is the sensor" — and, honestly, a multi-year build.

---

## Context — the fork ADR 0043 deliberately did not take

ADR 0043 ratified heqk as the rpi-native **substrate** but, in D5.6, kept a **monitored Linux guest VM** for the app tier (the HYDRA 11-service container stack, Mission Control, the api/planner/rbac tokio services), calling "replace Linux on every tier at once" a **rejected big-bang** and "Pi-first + Linux-guest-app-host" the bounded, reversible path. A deep Product-Cortex discovery (2026-07-25, 4 agents) surfaced the resulting fork and put it to the operator:

- **(A) Demote Linux to a sandboxed guest** — the ADR-0043 ratified plan; reachable in quarters; **does not eliminate Linux.**
- **(B) True zero-Linux SOC** — natively rebuild (or off-device-host) the Wasm module runtime, the switching/filtering dataplane, Wi-Fi AP, storage+filesystem, and the detection catalogue on heqk; **multi-year**, because HookProbe's product identity (Wasm-modules + containers + OVS + hostapd) has **no analogue on heqk today** (and host-EDR has no conceptual analogue at all — heqk has no process/exec model).

The operator chose **(B)**. This ADR records that choice, its scope, and the one sub-decision it defers.

---

## Decision

### D1 · Zero Linux on the CM5 device — supersedes ADR 0043 D5.6 **[vision]**
On the rpi-native tier, **nothing Linux runs on the CM5**: not as substrate (already ADR 0043), and now **not as an app-host guest** either. ADR 0043 D5.6's Linux-guest app tier is **superseded**; [ADR 0041](0041-container-vm-overlay-management.md)'s Linux-guest-under-VMM overlay is **out of scope for CM5** (it remains valid for the UEFI/amd64 tiers). The Zone-4 VMM is not on the CM5 critical path.

### D2 · Scope: **CM5 ONLY**, for this epic — narrows ADR 0043 D1 **[partial]**
ADR 0043 D1 scoped "CM5 first, then Pi5/Pi4." The operator narrows this epic to **CM5 only**. Pi5/Pi4 heqk and every non-aarch64 tier (amd64/N100/UEFI/cloud — which **keep Linux/bootc permanently**) are explicitly **out-of-scope-for-now**, not dropped. One board, so every gap is chased against one HAL.

### D3 · The app tier is native-on-heqk **or** hosted off-device — an **open M6 sub-decision** **[vision]**
"Zero Linux on the device" does not by itself say *where the heavy app tier runs*. Two sub-paths, resolved at Phase M6 (not now, and not blocking Phase 0):
- **B1 — native-on-heqk:** a `no_std` reimplementation of the module runtime + a native equivalent of the heavy stateful services. Maximal ownership; the true multi-year weight; the "win the kernel, risk losing the SOC" danger the discovery named.
- **B2 — hosted off-device (recommended default):** the CM5 is a **pure heqk sensor/enforcer**; Mission Control + HYDRA + the heavy tokio services run on a **hosted control plane / edge node**, consistent with [ADR 0009](0009-soc-brain-edge-cloud.md) and CLAUDE.md's "standalone by default, cloud is additive." This keeps *zero Linux on the CM5* **without** a multi-year native container rebuild, and is the pragmatic realization of B. The **on-device Wasm detection host is required in either sub-path** (it is the product's detection engine, not "app tier") — B1/B2 only decides where the *heavy stateful* tier lives.
`security-auditor`/`product-steward` gate the M6 choice; until then, plan for B2 as the tractable default and treat B1 as a per-module differentiator decision.

### D4 · What "zero Linux" requires — the component contract **[vision]**, ranked
The M1-Linux SOC (metal-proven, `BuildPlan.md` M1 milestone) is the acceptance spec. Each capability becomes a heqk build target with **no Linux fallback on CM5**:
1. **Userspace-server substrate** — ELF/multi-page EL0 loader + real syscall surface + caps *enforced not asserted* (the keystone; every isolation claim depends on it).
2. **Wasm/WASI host as an EL0 server** — runs the actual signed `.wasm`/`.cwasm` module catalogue (napse-dpi/aegis-guard/qsecbit/dnsxai) *on heqk* (ADR 0016/0017 signing ports).
3. **Writable storage + minimal FS + sealed retention store** (eMMC write path; today read-only).
4. **Detection-catalogue + separation-matrix parity** in RFC 9669 — the release-blocking security floor (Gate 0.7 30-row matrix + Gate R) must re-pass **on heqk metal**.
5. **Dataplane** (native switching/filtering/mirror to replace OVS+nft).
6. **Net stack as an EL0 service + control-plane API.**
7. **Wi-Fi AP mode on CYW43455** (FullMAC AP — the SASE-edge default; unstarted; the longest single-driver pole).

### D5 · The honesty floor — do not overclaim **[realized: this clause]**
heqk today is a **QEMU-green capability-microkernel core with thin, single-run, polling-only CM5 bring-up** — **not a running SOC.** `PRODUCTION_READINESS.md`'s "23/23 GREEN, metal-proven" describes single bench runs; `validate.sh` gates **QEMU only**. Detection/TCP-stack/drivers currently link **into the one kernel image** (a microkernel-shaped monolith). No external claim of "zero-Linux HookProbe SOC" is permitted until D4's items — at minimum #1, #2, #4 — are green on heqk metal under a reproducible gate. `market-intelligence` enforces.

---

## Consequences

- **The scope is honestly enormous** — ADR 0043 called exactly this "big-bang" and rejected it; the operator has now re-decided it with eyes open, mitigated by (a) **CM5-only** (D2), (b) **B2 off-device app tier** as the default (D3) which removes the container-rebuild weight, and (c) **component-by-component gating** (D4 order; each step testable; the Linux M1 stays the canonical rpi-native shipping image until each heqk component passes its metal gate).
- **Reversibility:** the Linux M1 image keeps shipping on rpi-native until the U1–U6 unbuild (`MIGRATION-heqk.md`) deletes it component-by-component, gate-by-gate — no capability is removed from the shipping image before its heqk replacement passes on metal.
- **ADR 0043 stands** as the substrate keystone; only its **app-tier scoping (D5.6)** and the "Linux-guest is the reversible path" framing are superseded. ADR 0041 is CM5-out-of-scope (survives on UEFI). `MIGRATION-heqk.md` M6 is rewritten from "stand up the Linux guest" to "the app tier is native-or-hosted, no on-device Linux."
- **The biggest risk remains #5 from the discovery:** delivering a secure kernel that boots Linux-free but is not a HookProbe SOC. D4's ordering (server substrate → Wasm host → detection parity first) is the mitigation: prove the *product* runs on heqk early, not last.

## Alternatives considered
- **(A) demote-to-guest (ADR 0043 D5.6 as-was)** — rejected by the operator in favor of true zero-Linux, accepting the multi-year cost for full substrate + app-host ownership on CM5.
- **B1 native-everything vs B2 hosted-app-tier** — not decided here; deferred to M6 (D3), with B2 the recommended tractable default.
