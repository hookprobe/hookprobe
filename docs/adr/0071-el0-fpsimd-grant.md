<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ADR 0071 — FP/SIMD for one granted EL0 server (Conductor KR-1 = Neuro R2)

**Status:** proposed (2026-11-24). Needs an operator decision: it changes the EL0 excursion entry and exit, which is
security-sensitive (G46 security review before the shipping flavour takes it).

## Context

`os/conductor/KERNEL_REQUESTS.md` KR-1 (Neuro `12` R2). Every EL0 server is scalar integer today. Nothing writes
`CPACR_EL1` or `CPTR_EL2`. The thread frame has no V registers, and every crate is `softfloat`. Integer GEMV is
estimated at 10–30× slower than NEON SDOT, which rules out the language tier (Neuro doc 30, explainer ftFg =
Qwen3-1.7B Q8_0).

### R0, what the CM5 has (read from this board's `[T0-inv]` inventory on metal)
| Register | Value | Meaning |
|---|---|---|
| MIDR | `0x414fd0b1` | Cortex-A76 r4p1 |
| ID_AA64PFR0 | `0x1100000010111112` | FP = 1, AdvSIMD = 1 (both with FP16), **SVE = 0** |
| ID_AA64ISAR0 | `0x0000100010211120` | **DotProd = 1** (SDOT/UDOT), RDM = 1, Atomics = 2 |

Still unread: what the firmware leaves in `CPTR_EL2` (TFP), `CPACR_EL1` (FPEN) and `SCTLR_EL1` (A). The `t0inv`
build reads them read-only from this change on (`r0.*` lines). HBoot writes none of them today. One metal boot of a
`t0inv` HBoot answers this; it has to be a USB flash because HBoot is not updated by OTA.

## Decision (proposed)

The request's design, unchanged except where noted:

1. **One `FpSimd` server, by a static build-time flag** (first step). A capability comes later, together with KR-2's
   manifest grants.
2. **FPEN only inside that server's excursion.** On entry, `CPACR_EL1.FPEN = 0b01` (EL0 only). On exit it goes back
   to trapping. EL1 stays softfloat, and a vector instruction in EL1 still traps.
3. **A 528-byte save area** (V0–V31, FPCR, FPSR) owned by that server. It is saved on exit and restored on entry.
4. **One owner, nothing to scrub.** If a second `FpSimd` server appears, or once ADR 0060 SMP lands, the registers
   are zeroed or switched on every change of owner. This is a hard precondition written into the code, not a note:
   a second grant fails the build.
5. A trap in a server without the grant ends that excursion, as any fault does today.
6. That one server's crate builds hard-float (`aarch64-unknown-none`) and is still loaded by `elf.rs` with W^X in its
   own address space.
7. **Alignment:** clear `SCTLR_EL1.A` explicitly in the same write that sets M/C/I/WXN (`mmu.rs`, `mmu_cm5.rs`).
   The model region and the arena must be Normal cacheable memory.
8. If R0 shows `CPTR_EL2.TFP = 1`, HBoot clears it before entering EL1, with only that bit changed.

Not decided here: FP in EL1, lazy FP, SVE/SME (absent), KR-2.

## Gates (from the request)

QEMU:
- `[P-fpsimd-align]`, `[P-fpsimd-grant]` (SDOT known answer), `[P-fpsimd-deny]`, `[P-fpsimd-leak]`,
  `[P-fpsimd-persist]`.

Metal (CM5):
- the same four;
- worst data-plane loop gap unchanged;
- the 33-row separation matrix unchanged;
- an excursion round trip within 8% of 388 ns (ADR 0067).

## Alternatives

| | Option | For | Against |
|---|---|---|---|
| A | **Per-server grant, eager save/restore (this ADR)** | One owner, so no leak by construction; small | Saves and restores 528 B on every excursion of that server (measured by the 8% gate) |
| B | Lazy FP (trap on first use, then switch) | Cheaper when the server does not use FP | The classic leak class (LazyFP); more states to prove |
| C | No FP; integer kernels only | No kernel change | Rules out the language tier on device (doc 30) |
| D | FP in EL1 for the engine | Fastest | Puts tensor maths in the kernel; rejected by the request itself |

## Order

After the 72 h soak, never in the soak candidate:
1. R0 metal readout (one `t0inv` boot).
2. This ADR accepted.
3. Implementation behind a bench feature, with the QEMU gates.
4. Metal gates.
5. Shipping only after the G46 review.
