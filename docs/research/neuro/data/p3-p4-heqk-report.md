# el0-neuro inside heqk (QEMU) — P3/P4 report for HomePods (2026-11-18)

> Plan: `docs/research/neuro/14` P3 (correctness) and P4 (cost).
>
> **Throwaway only:** a scratch worktree of `main` at `c70bd4d3`, removed afterwards. **Nothing in
> `os/kernel` was committed.** The exact kernel-side changes are in
> [`p3-heqk-throwaway.patch`](p3-heqk-throwaway.patch). They cover 4 files and 378 lines:
> - the test driver `kernel/src/neuro.rs`;
> - a `neuro` feature;
> - a `build_el0_crate` call;
> - the boot hook.
>
> Before applying the patch, create the symlink `os/kernel/el0-neuro -> ../neuro/el0-neuro`.
>
> Toolchain: `nightly-2026-07-20`. QEMU 11.1.3 virt, cortex-a72, on Apple M5 Pro.
> Raw lines: [`p3-p4-qemu-boot.txt`](p3-p4-qemu-boot.txt).

## What ran

`kernel/src/neuro.rs` loads `el0-neuro` like `hsh.rs` loads `el0-hsh`:
- its own `El0As`;
- ELF segments inside its window, at the proposed QEMU base `0xBE00_0000`;
- **21 RW pages** for the 64-device table (hsh's loader allows 8);
- a 16 KiB stack and a 16 KiB IO region.

It is driven through the proposed ABI as synchronous bounded excursions (`el0as::excursion`, 2 s budget
on QEMU).

## Results

| Check | Result |
|---|---|
| `CMD_INFO` | 64 devices, **1,296 B per device**, 21 RW pages |
| **Golden replay** (`neuro-core/tests/golden.txt`: 3 devices × 400 h, 8,567 events) through `CMD_EVENTS` + `CMD_CLOSE_HOUR` | **PASS — 1,200 / 1,200 hour closes bit-exact** (score and all five parts) against the Python reference. State persists correctly in the server's `.bss` across 2,400+ excursions. |
| **Fault containment** | **PASS**:<br>a 15-byte batch → `ST_BAD_INPUT`;<br>device 999 → `ST_BAD_INPUT`;<br>hour 24 → `ST_BAD_INPUT`;<br>`CMD_SELFTEST_FAULT` (a panic in EL0) → `ST_PANIC`, data pages restored, kernel alive, the next `CMD_INFO` → OK |
| Rest of the boot | `[ALL] ... GREEN` unchanged |
| **Load:** 64 devices, 38,400 events in 75 batches of 512 | 88 ns/event gross; **51 ns/event net** of the 18 µs empty-excursion overhead; largest batch excursion 118 µs |
| **Hour close for all 64 devices** | **148 µs** (plan limit: 20 ms) |

**These timings are QEMU TCG on an Apple M5 Pro, not timing-faithful.** They show orders of
magnitude, not A76 numbers. They put the engine roughly two orders of magnitude inside its budgets:
- 1K events/s at 88 ns costs ≈ 0.01% of a core;
- the hour close fits easily inside lansvc's 20 ms excursion budget.

CM5 metal numbers are P6.

## Observations for HomePods

1. **A stale tick at the first excursion.** The test runs from the boot path (inside the tick handler's
   exit branch), so the driver first stops the physical timer, as `cm5_scheduler_demo` does. The **first**
   excursion afterwards still ran to the 2 s watchdog and reported a fault (`status 6 in 1,987,317 µs`).
   Every later excursion was clean.

   Our reading is that a level-sensitive scheduler tick was still pending at the GIC and fired when the
   excursion unmasked IRQs at EL0. This is the hazard the `cm5_scheduler_demo` comment describes. It is
   a test-context artefact, but worth knowing for any server whose first excursion follows a timer
   shutdown.
2. **Without stopping the tick first,** calling an excursion from inside the tick handler's exit branch
   re-entered that handler. It then panicked in the P7c block (`read_volatile` precondition,
   `main.rs:11684` in the patched tree). Excursions are not meant to run from that context. We note it
   only so nobody repeats the experiment that way.
3. **The loader's writable-page cap.** `hsh.rs`-style loaders cap writable pages at `RW_MAX = 8`;
   `el0-neuro` needs 21 (83 KB `.bss`). The page cap is per loader, so a real integration sets its own.

## Not shown here (needs the real integration, plan P5/P6)

- **The effect on the production main loop's worst gap and on `[IDS-BENCH]` ns/pkt.** That needs the
  engine called from the serve loop, not the boot path.
- Data-plane hooks, fingerprinting and the hourly timer.
- CM5 timing.
