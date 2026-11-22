# arch-x86_64 — heqk on x86_64, X1 skeleton

ADR 0047 D1 makes heqk the operating system on x86_64 too: N100 appliances, x86 cloud VMs and the PoP hosts.
This crate is **X1**, the first step. It proves the x86_64 CPU substrate heqk needs, as a standalone UEFI
application.

**Not wired to the kernel yet.** That waits for X0: the portable network logic moving out of `arch-aarch64`, and
the kernel→arch calls going through `hal` traits. The decisions this crate only *implements* are recorded in
**ADR 0068 (pending)**: the boot/trust chain without `hboot`/EL2, the entropy policy, and the isolation model.
Nothing here merges before that ADR is accepted.

## What it proves (one serial marker per stage)

| Marker | Stage |
|---|---|
| `[X1]` | Entered as a PE32+ UEFI application (zero dependencies, raw UEFI FFI like `efiboot`) |
| `[X1-mem]` / `[X1-ebs]` | Takes the firmware memory-map census, then calls ExitBootServices (retried once if the map key changed). The firmware is gone after this. |
| `[X1-gdt]` | Its own GDT (kernel/user code and data) and TSS: `rsp0` for entries from CPL3, IST1 so a #DF never runs on a broken stack |
| `[X1-idt]` | Its own IDT with `x86-interrupt` handlers. An `int3` self-test is handled and execution resumes. |
| `[X1-paging]` | Its own 4-level page tables: a supervisor-only identity map of 0–4 GiB, with MMIO uncached. One user window holds an RX code page and an RW+NX stack page. NX, SMEP and SMAP are switched on where the CPU has them. |
| `[X1-rng]` | RDSEED health check (64 samples; repetition, stuck-at and bit-toggle tests). It is **FAIL-CLOSED**: there is no RDRAND, timer or counter fallback. |
| `[X1-apic]` | LAPIC periodic timer interrupts, with the 8259 PICs masked |
| `[X1-ring3]` | Code runs at CPL3 and returns through SYSCALL (STAR/LSTAR/FMASK) |
| `[X1-ring3-iso]` | A CPL3 read of kernel memory raises #PF (present, user). A CPL3 execute from the NX stack raises #PF (present, user, fetch). |
| `[X1] PASS` | QEMU exit 33, through `isa-debug-exit` |

## Run

```bash
./run-qemu.sh                 # q35 + OVMF; KVM (-cpu host) if /dev/kvm is usable, else TCG (-cpu max)
X1_ACCEL=tcg ./run-qemu.sh    # force TCG
tests/negative.sh             # the checks must be able to FAIL
```

`tests/negative.sh` runs three negative controls. Each must fail with exit 35 and the right message.
- **No RDSEED** (`-cpu …,-rdseed`): stops at `[X1-rng] FAIL-CLOSED`.
- **Mutant build with the kernel identity map user-accessible** (SMEP/SMAP off): the isolation check reports "NOT refused".
- **Mutant build with the user stack executable**: the NX check reports "NOT refused".

The mutants are built from a temporary copy of the crate, never from the source tree.

Requirements: the pinned nightly from `../rust-toolchain.toml` (rust-src, for `build-std`), `qemu-system-x86_64`,
and OVMF (`apt install ovmf`; override the firmware paths with `OVMF_CODE`/`OVMF_VARS`).

## Next (X1 → X2)

- **Interrupt controllers:** x2APIC and IOAPIC/MSI, with ACPI MADT parsing in place of the fixed xAPIC base.
- **Memory:** a physical frame allocator built from the saved memory map; higher-half kernel mappings; KPTI
  decisions (ADR 0062 x86 matrix).
- **Devices:** PCIe ECAM (ACPI MCFG); virtio-pci net and blk, reusing `arch-aarch64`'s `pci.rs`/`virtio_transport.rs` logic after X0.
- **Kernel wiring:** `hal` trait implementations, so the kernel builds for x86_64 once X0 lands.
- **BPF:** the interpreter at first; an x86 JIT later.
