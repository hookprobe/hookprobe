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
| `[X1] PASS` | Every X1 stage above passed |
| `[X2-acpi]` | The RSDP is taken from the UEFI configuration table before ExitBootServices. RSDP → XSDT → MADT + MCFG follow, with every table signature-, length- and checksum-checked (firmware tables are untrusted input). |
| `[X2-frames]` | A physical frame allocator built from the memory map saved at ExitBootServices: conventional and boot-services RAM only, never loader/ACPI/MMIO. Adjacent ranges are merged and truncation is reported. 64 frames are allocated and checked. |
| `[X2-ioapic]` | Every I/O APIC from the MADT: its version and input count, with every input masked |
| `[X2-lapic]` | **x2APIC** (MSR interface) when the CPU has it, otherwise **xAPIC** (MMIO). Both paths are tested. |
| `[X2-pci]` | PCIe enumeration through ECAM (read-only), finding the modern virtio-pci functions (net, blk) and their virtio 1.x capabilities (common / notify / ISR / device config) |
| `[X2] PASS` | QEMU exit 33, through `isa-debug-exit` |

Page caching follows the firmware memory map. A 2 MiB page is write-back only if it overlaps RAM; LAPIC, IOAPIC,
ECAM and BAR windows are uncached.

## Run

```bash
./run-qemu.sh                 # q35 + OVMF; KVM (-cpu host) if /dev/kvm is usable, else TCG (-cpu max)
X1_ACCEL=tcg ./run-qemu.sh    # force TCG
tests/negative.sh             # the checks must be able to FAIL
```

`run-qemu.sh` attaches a modern virtio-net (user-mode net with `restrict=on`, so nothing leaves the host) and a
virtio-blk backed by a throwaway 1 MiB file. `X1_CPU=host,-x2apic` exercises the xAPIC path.

`tests/negative.sh` runs four negative controls. Each must fail with exit 35 and the right message.
- **No RDSEED** (`-cpu …,-rdseed`): stops at `[X1-rng] FAIL-CLOSED`.
- **Mutant build with the kernel identity map user-accessible** (SMEP/SMAP off): the isolation check reports "NOT refused".
- **Mutant build with the user stack executable**: the NX check reports "NOT refused".
- **No virtio devices on the bus** (`X1_NODEV=1`): the X2 PCIe stage fails instead of passing vacuously.

The mutants are built from a temporary copy of the crate, never from the source tree.

Requirements: the pinned nightly from `../rust-toolchain.toml` (rust-src, for `build-std`), `qemu-system-x86_64`,
and OVMF (`apt install ovmf`; override the firmware paths with `OVMF_CODE`/`OVMF_VARS`).

## Next (rest of X2)

- **virtio-pci drivers:** map the BARs, run the modern transport (common config, feature negotiation, virtqueues),
  then virtio-net TX/RX and virtio-blk reads. Reuse `arch-aarch64`'s `virtio_transport.rs` logic after X0.
  **No virtio-rng in the cloud profile** (operator decision 2026-11-22: entropy on x86 comes from RDSEED).
- **Interrupts:** MSI-X routing for the virtio queues; IOAPIC redirection for legacy GSIs.
- **Memory:** kernel W^X (section-aware mapping from the frame allocator), higher-half kernel mappings, and KPTI
  decisions (ADR 0062 x86 matrix).
- **Kernel wiring:** `hal` trait implementations, so the kernel builds for x86_64 once X0 lands.
- **BPF:** the interpreter at first; an x86 JIT later.
