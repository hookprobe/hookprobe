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

## KR-3: Conductor C1 in the kernel (added 2026-11-24)

| Item | Answer |
|---|---|
| 1. `CondCtr` (2058, 2) + `CondEpoch` (2060, 2) DataVolume regions | **Yes.** They fit the free space after `G19Ctr` (2056..2058). Each writer arms only its own two sectors (Gate 2), and the `[P-datavol]` disjointness check gets both. |
| 2. One counter mechanism | **`g19ctr` grows a magic parameter** (`load(dev, lo, magic)` / `advance(dev, lo, magic)`); the kernel does not link `conductor_core::durable`. One implementation, kernel-owned. The drift test keeps checking the layout against the kernel source. |
| 3. Delegation + cache-salt keys = `HKDF(SRK, "HQ-conductor-delegation-v1" / "HQ-conductor-salt-v1")`, EL1 only | **Yes.** This is the same pattern as the owner journal key, and consistent with the operator rule that the identity key and Noise stay in the kernel (2026-11-11). They are never mapped to EL0 (`AT S1E0R` gate). G46 review before shipping. |
| 4. One EL1 service `conductor_sign` (the harness's only new syscall); pairings as an owner-journal record kind | **Yes, as designed.** Signing reuses the kernel's existing Ed25519. The pairing record is a new owner-journal kind with the existing re-auth + journal rules. |
| 5. Leases in the data plane (drop + record + suspend a worker frame outside its lease) | **Needs an operator decision first.** It is new enforcement on the data plane, and the standing rule is "observe by default; drop only genuine DDoS; legit always passes" (enforcement separation). A worker's own egress outside its lease may be the exception the operator wants, but it has to be decided explicitly, with the separation-matrix gate. Alternatives: observe + record + revoke the lease (no drop), or drop only the worker's frames. |
| 6. Ledger records in the sealed evidence log (`fslog`), chain/anchor check on top | **Yes:** one new record type. It shares the evidence ring's capacity, so the record budget goes in the same PR. |

Order: after the 72 h soak, and after ADR 0071 (Conductor directed execution) is accepted. Steps: (1)+(2) first
(small, testable like `[P-g19ctr]`), then (3)+(4), then (6). (5) waits for the decision above.
