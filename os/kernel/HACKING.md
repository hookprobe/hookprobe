# Hacking HEQK Core (Hardened Edge Quantum-safe Kernel)

Workspace for the custom Rust aarch64 microkernel (`ARCHITECTURE.md`, `buildPlan.md`).

## Layout
```
kernel/        bin crate: _start seam (kmain), panic handler, linker.ld, build.rs
hal/           arch-agnostic traits (Console; Mmu/Timer/Irq land with their phase)
arch-aarch64/  the ONLY arch-aware crate: boot.s, vectors.s, PL011 UART, semihosting
abi/           shared kernel<->userspace ABI (syscall numbers) — stub until P3
```
`kernel` uses `arch_aarch64` only at the boot/console seam; everything else goes through `hal` traits. No `cfg(target_arch)` in `kernel`.

## Prerequisites
- Rust **nightly** with `rust-src` + `llvm-tools` and the `aarch64-unknown-none-softfloat` target
  (all pinned in `rust-toolchain.toml`; rustup installs them on first build).
- `qemu-system-aarch64` (tested with 8.2.2).

## Build & run
```sh
cargo build              # cross-builds the aarch64 ELF (target set in .cargo/config.toml)
cargo run                # builds + boots it under QEMU virt (runner in .cargo/config.toml)
```
`cargo run` exits cleanly because the P0 self-test terminates QEMU via ARM semihosting.

### Exercise the EL2->EL1 drop
QEMU `virt` starts at EL1 by default; to boot at EL2 and exercise the drop in `boot.s`:
```sh
qemu-system-aarch64 -M virt,virtualization=on,gic-version=3 -cpu cortex-a72 -m 512M \
  -nographic -serial mon:stdio -semihosting \
  -kernel target/aarch64-unknown-none-softfloat/debug/kernel
```
Either way you should see `hello from EL1`.

### Debug (GDB)
```sh
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio \
  -semihosting -s -S -kernel target/aarch64-unknown-none-softfloat/debug/kernel &
gdb-multiarch target/aarch64-unknown-none-softfloat/debug/kernel -ex 'target remote :1234'
```

## What P0 does (and how to read a good boot)
`_start` (arch-aarch64/src/boot.s): parks secondary cores → sets the stack → drops
EL2→EL1 if needed → sets `VBAR_EL1` → zeroes `.bss` → calls `kmain`. `kmain`
(kernel/src/main.rs) prints the banner + current EL over PL011, then triggers
`brk #0` to prove the vector path: the handler (arch-aarch64/src/exception.rs)
reports `ESR_EL1` (EC=0x3c = AArch64 Breakpoint) and exits. Expected output:
```
 HookProbe microkernel — P0 skeleton
 boot: EL->EL1 OK | .bss zeroed | VBAR_EL1 set
 hello from EL1
 self-test: triggering synchronous exception (brk #0)...
[EXCEPTION] Sync/SPx (idx=4)  ESR_EL1=0x...f2000000  EC=0x3c  ...
  -> caught by VBAR_EL1 handler
```

## What P1 adds (preemptive multitasking — DONE)
`kmain` now: inits a **kernel heap** (`kernel/src/heap.rs`, bump allocator) →
spawns 3 worker threads (`scheduler::spawn` + `arch_aarch64::thread::make_thread`) →
brings up **GICv2** (`arch-aarch64/src/gic.rs`) + the **generic timer** at 100 Hz
(`timer.rs`, INTID 30) → enables IRQs → idles. The timer IRQ enters `irq_entry`
(`vectors.s`), which saves the full trap frame, calls `handle_irq` (kernel), and
the **round-robin scheduler** (`scheduler.rs`) returns the next thread's SP to
switch to. Expected output ends with interleaving like:
```
 --- enabling IRQs; threads interleave below (A/B/C + own counter) ---
A0 B0 C0 C1 A1 B1
 --- 60 ticks elapsed: preemptive multitasking verified ---
```
Each thread's counter advancing across the interleave proves context
save/restore. HAL boundary held: `kernel` uses `hal::{Console,Timer,IrqController}`
+ the arch seam; no `cfg(target_arch)` in `kernel`.

## Next (P1b → P2, per buildPlan.md §5)
- **P1b — MMU/paging** (still OFF; running identity physical): MAIR/TCR/TTBR/SCTLR,
  ASID-tagged, behind a `hal::Mmu` trait; a real physical frame allocator.
- **P2 — capabilities**: CNodes, untyped→retype, CSpaces, CDT recursive revoke.
- Then P3 (EL0 + SVC syscalls), P4 (IPC + zero-copy ring), P5 (virtio-net + a
  BPF verdict = the north-star packet).
