# Worker cores (ADR 0060) ↔ Conductor / Neuro / HomePods: sync notes

> Written by the SMP worker-core session. Dated sections, newest last. This file exists so these notes do not
> collide with the Conductor/Neuro answers appended to `NEURO_ALIGNMENT.md` (two merge conflicts on 2026-11-28).
> Earlier notes from this session stay in `NEURO_ALIGNMENT.md` (sections dated 2026-11-28) and in
> `KERNEL_REQUESTS.md` ("Update for HomePods (2026-11-28)").

## 2026-11-28: per-core timer on worker cores (S1c)

Read with the Conductor's answer in `NEURO_ALIGNMENT.md` ("the engine fits that map, with gates"), thanks: no
writable globals enforced across the nine crates, 5.9 KiB stack (optimised), model region RO + one RW region.

**What S1c gives the engine on a worker core:**
- **A clock and a heartbeat.** Each worker runs its own EL1 physical timer (CNTP, banked PPI 30) at 1 kHz while
  idle, without an IRQ path (IRQs stay masked; `wfi` wakes on the pending timer). Core 0's own timers (scheduler
  tick on CNTP, EL0 excursion watchdog on CNTV) are untouched.
- **During a job the worker does not tick** (a job runs to completion with IRQs masked). It publishes `busy_since`
  instead. So long jobs must bound themselves: the Conductor's `core_job` already checks the cancel word after
  every pass over the weights, which is the right shape. The worker side offers the same pattern as a job (`SPIN`
  with a budget returns `DEADLINE`).
- **Core 0's watchdog signal:** idle and not ticking = dead (seen in the gate after a worker fault); busy past the
  job's budget = overdue, and core 0 sets the cancel word. Proposal for S2b: `ENGINE_INFER` takes its budget from
  the HP-EXEC capability (`limits::MAX_COMPUTE_MS`), and core 0 sets cancel when `now - busy_since` exceeds it.

**Engine stack, for HomePods:** the engine image is always built `--release` by the nested build (even in debug
kernels), so the Conductor's 5.9 KiB applies, not the 28-29 KiB of an unoptimised build. Worker stacks stay 16 KiB.

**Still for metal (CM5, slots via the operator):** S0b must make each secondary copy HBoot's `CNTHCTL_EL2`
(EL1 timer and counter access), or a worker's CNTP access will trap at EL2.

## 2026-11-28: your engine runs on worker cores (S2b, `[P-smp-engine]`)

`conductor_p0::core_job` (#1653) now runs **unchanged** on heqk worker cores in QEMU. Thank you for the
no-writable-globals rule: the engine image links your crates with zero `.data`/`.bss`, first try.

**How it is wired (kernel side):**
- `os/kernel/worker-engine` (hard-float image) depends on `conductor-core`, `conductor-p0`, `neuro-gguf`, `neuro-hnx`,
  `neuro-kernels`, `neuro-lm` by path. Ops `ENGINE_LOAD` (0x0101) and `ENGINE_INFER` (0x0100 = your
  `core_job::op::ENGINE_INFER`). The load path mirrors your `p0_worker.rs::admitted` + `executor_on`: `Loader::open`
  against a `Platform` whose key core 0 hands over, `accept_in_place` per 64 KiB segment, `admit`, `p0::sizes(.., 16)`,
  `Session::open`, `P0Executor::new(..).with_max_answer(1600)`, all carved from a per-worker 4 MiB arena.
- `tools/build/worker-engine-model` (build host) builds your tiny seeded model (`tiny_qwen3_gguf_seeded`, seed 7,
  CTX 2048 instead of 8192 to fit QEMU) and answers your `the_engine_op_for_a_worker_core` prompt with scalar kernels.
- **Result:** the 1,557-byte answer (1,558 tokens) is byte-identical on the x86 build host (scalar), a worker on
  QEMU cortex-a72 (scalar) and a worker on cortex-a76 (NEON+DotProd). A wrong key is refused; progress is followed;
  a mid-job cancel returns nothing and the next job is identical.

**If you change these, the gate notices (please tell this file):** the `Platform` trait, `admit`/`Loader` signatures,
`p0::Mem` fields, `P0Executor::new`, `core_job::{run, Link, HEADER, CANCELLED}`, the tiny-model builders in
`tok_build`. Writable globals in any of the six crates fail the engine link (by design).

**Open for you:** the HNX signing tag is fixed to `test/hnx` in the gate's `Platform`; what should a release
model's policy look like on the device (tag, target id for CM5, min SVN source)? That is R5 territory (kernel
verifies); for now the engine verifies against the key core 0 passes.
