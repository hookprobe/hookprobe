# os/neuro — HookProbe Neuro, stage 1: temporal security engine

Stage 1 of the decision in [`docs/research/neuro/13`](../../docs/research/neuro/13_FINAL_ARCHITECTURE_DECISION.md),
approved 2026-11-18:
- the per-device behavioural memory ("Neural DNA") as integer-only `no_std` Rust;
- packaged as an EL0 excursion server for heqk;
- **with no kernel change**.

The engine **observes and scores**. It never decides enforcement (ADR 0023, contract C9).

| Crate | What | Target |
|---|---|---|
| [`neuro-core/`](neuro-core/) | the engine: integer streaming DNA. No `unsafe`, no allocation, no float, no dependencies. | any (`no_std`); tests on the host |
| [`el0-neuro/`](el0-neuro/) | the EL0 server: shared-IO ABI (`hal::neuroabi` v1, shared with the kernel host `os/kernel/kernel/src/neuro.rs`), 64 device slots in `.bss`, commands EVENTS / CLOSE_HOUR / RESET_DEV / INFO | `aarch64-unknown-none-softfloat` |

## Verification status — read before relying on it

| Claim | Status | Evidence |
|---|---|---|
| The integer design loses nothing against the float DNA | **measured** (Python integer reference vs float, same experiments) | synthetic, 5 seeds: AUC 0.999 = 0.999 (10 days); **0.929 vs 0.928** (12 h cold start); identical per-kind detection, drift alerts and nuisance. IoT-23: Hue honeypot **2.00 alarms/day in both**; onset 14/14, all novelty-driven, in both. `docs/research/neuro/data/e-n0-*` |
| The Rust port equals the integer reference bit for bit | **passed** (host, rustc 1.99.0-nightly 9f36de775 2026-07-19, the heqk pin) | `neuro-core/tests/golden.rs`: 1,200 hour closes (155 alarms, Bloom rotations at 168/336 h), every score part and the final profile bit-exact; 27 unit checks; **1,296 B per device** (real struct size) |
| `el0-neuro` builds for heqk | **passed** for `aarch64-unknown-none-softfloat`, QEMU and CM5 variants; clippy clean | CM5 ELF: code 5.4 KB RX at 0x1_4026_0000, rodata 512 B R, **.bss 83 KB RW with 0 bytes in the file**: about 6 KB embedded in the kernel image. **Zero FP/SIMD instructions** (objdump) |
| Peer keys for the data plane (`neuro-core::peerkey`) equal the Python reference bit for bit | **passed** (host) | `neuro-core/tests/peerkey.rs`: 3,000 keys in 5 modes and 4,000 name-table operations (64-entry table, evictions) identical to `unsw_to_d1.py`; `NameEntry` 32 B, `NameTable<4096>` 128 KiB |
| Runs in QEMU-heqk | **passed** (2026-11-22, behind the kernel feature `neuro`, off in every shipping image) | `os/kernel/tools/neuro-qemu.sh`: `[P-neuro-golden]` 1,200/1,200 closes bit-exact through the permanent ABI (`hal::neuroabi`, v1.1) + EL1 reply validation; fault containment, complaint/reset, backpressure, isolation. Design: [`docs/design/heqk-neuro-integration.md`](../../docs/design/heqk-neuro-integration.md) |
| Data-plane adapter (doc 20 §2) | **passed** (host parity with the reference converter + `[P-neuro-dp]` in QEMU) | [`neuro-dp/`](neuro-dp/): frames -> fingerprints in EL1, bounded state |
| Runs on CM5 | **not started** | needs a bench slot (design doc §9 P3) |

## Run the checks

```bash
cd os/neuro/neuro-core && cargo test --release -- --nocapture
```

```bash
cd os/neuro/el0-neuro && cargo build --release --features cm5
```

To regenerate the vectors (deterministic; also regenerates `neuro-core/src/log2_lut.rs`):

```bash
python3 -I tools/neuro-research/gen_golden.py os/neuro/neuro-core
```

## Design points that matter for heqk

- **Memory:** about 1.2–1.3 KiB per device, including the hour aggregator. Python estimate 1,214 B;
  the exact Rust size is printed by the golden test.
  - 64 devices take about 85 KiB of **zero-initialised `.bss`**, initialised per slot on first use.
  - The table therefore adds nothing to the ELF the kernel embeds. The kernel image has ~33 KB of
    headroom; the server's code still counts against it.
- **Address range:** proposed at `0x1_4026_0000`, in the unused gap between `el0-lansvc` and `el0-hsh`
  inside the 4 MiB GB5 window. The whole server, including IO, ends before `0x1_4030_0000`.
- **State:** lives in the server's own pages. The kernel must keep them across excursions, as for
  `el0-wpa`. A fault or reset loses the memory, and the DNA relearns through the cold-start path.
- **Privacy and input:**
  - the kernel sends **fingerprints**, not addresses or names;
  - every record is bounds-checked;
  - a malformed batch returns `ST_BAD_INPUT`;
  - a panic ends only the excursion.
- **Guarded learning:**
  - calm hours teach;
  - alarming hours teach only cold-slot statistics;
  - a new peer becomes normal after 6 alarming hours (8-entry pending table per device).

## Known open items

1. **DNS signal on quiet devices.** One NXDOMAIN in three queries is a 33% share and raises an alarm.
   The golden vectors show this, the float DNA has the same formula, and IoT-23 has no DNS to test it.
   It needs a minimum query count before the NX term counts. That fix belongs on a dev split of real
   DNS data, not here.
2. **Evidence only (decided by D1, `docs/research/neuro/17`–`19`).** On six months of real IoT traffic the
   engine detects every injected attack class but raises 72 benign deviations per device per week, and
   neither a DNS rule, service-keyed peers nor a per-device threshold makes it quiet without losing
   detection. Its result is therefore **evidence, never an alert**. The kernel-side wiring (HomePods) is
   specified in `docs/research/neuro/20`: service-keyed peer fingerprints (`neuro-core::peerkey`, below),
   an hourly `CMD_CLOSE_HOUR`, and a "behaviour deviation" evidence node with the driver named.
3. Multi-day benign traffic for the nuisance rate (`docs/research/neuro-engine` E-BM2).
