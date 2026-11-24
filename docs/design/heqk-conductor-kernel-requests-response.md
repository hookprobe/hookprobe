# Kernel side: response to the Conductor kernel requests (os/conductor/KERNEL_REQUESTS.md), 2026-11-24

Owner of `os/kernel/**` (HomePods session).

| Request | Answer | Where |
|---|---|---|
| **R0 readouts** | Mostly answered from this CM5's existing `[T0-inv]` metal inventory: Cortex-A76 r4p1, FP + AdvSIMD (FP16), **DotProd = 1**, SVE = 0. Added (read-only, `t0inv` build only) the readout of what the firmware leaves in `CPTR_EL2.TFP`, `CPACR_EL1.FPEN`, `SCTLR_EL1.A` and `HCR_EL2.E2H`; one USB-flashed `t0inv` boot reads them. | this PR (`hboot/src/t0inv.rs`) |
| **KR-1** FP/SIMD for one EL0 server | Accepted in principle, written up as **ADR 0072 (proposed)**: the request's design, plus two hard rules: a second grant fails the build until owner-switch scrubbing exists, and `SCTLR_EL1.A` is cleared explicitly. Needs operator acceptance and the G46 review. | `docs/adr/0072-el0-fpsimd-grant.md` |
| **KR-2** runtime workload loader | Agreed, and the request's order is right: (a) `HQW1` package + `workload` artifact type → (b) load-once at boot → (c) runtime install/update → (d) remove after ADR 0061 D3 (frame free lists). Signing policy (vendor root only vs owner-signed third party) is the real security decision and is the operator's, together with Neuro R5. An ADR follows once KR-1 is decided. | — |
| `el0-harness` behind a feature now | Fine. The harness has zero FP/SIMD and one syscall. It goes in as a bench feature like `neuro` did, with the size gate and no shipping change. Image headroom (shipping + neuro) is the constraint. | on request |

**Timing.** Nothing here enters the 72 h soak candidate. The soak runs current main as shipped (shipping set +
neuro). R0's metal boot needs a USB flash of a `t0inv` HBoot, so it goes after the soak. KR-1 implementation
starts after ADR 0072 is accepted.
