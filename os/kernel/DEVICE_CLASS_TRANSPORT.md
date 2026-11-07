# P11 — Device-Class Transport (the sDDF borrow) — frozen design

Status: **DESIGNED, not yet implemented.** This document is the implementable spec.
Researched against seL4's sDDF and validated against the existing HEQK code.

## Why

Today HEQK has the *same* SPSC ring protocol written twice (`kernel/src/packet.rs`
and `kernel/src/events.rs`), plus two hardware descriptor rings with opposite
ownership polarity (`gem.rs` `RXD_USED` bit0 = SW-owns; `rtl8111.rs` `OWN` bit31 =
NIC-owns), and the entire EL0 driver "transport" is a single `AtomicU32`
(`DRIVER_REPORT`, `SYS_DRIVER_REPORT=7`). P11 unifies these into one verified
queue ABI shared by every EL0 driver of a device class.

## The delta vs sDDF (this is the whole point)

sDDF assumes **drivers are trusted** (design doc §9.1). HEQK's threat model says an
EL0 driver is **UNTRUSTED**. So we take sDDF's structure and add four hardenings:

| # | Hardening | Why |
|---|---|---|
| H1 | Queue geometry (`capacity`) lives **only** in kernel-private memory | else the driver forges capacity -> OOB indexing |
| H2 | Kernel keeps a **private buffer-ownership table**; a descriptor is accepted only if the kernel believes the driver owns that buffer | sDDF's "a buffer is in at most one queue" is *cooperative*; HEQK must *enforce* it |
| H3 | **Copy-then-validate**: snapshot the 16-byte descriptor into kernel memory, then validate the copy | Cortex-A76 is Armv8.2-A with **no FEAT_LSE2** -> a 16-byte LDP is *not* single-copy atomic -> descriptors **can tear** |
| H4 | **DMA-address authority stays in the kernel**: the driver's HW-ring grant is **read-only**; only the kernel writes buffer bus addresses | BCM2712's IOMMU has **no stream IDs**, so a driver that can write descriptor address fields could DMA anywhere |

H4 is the strongest result: a fully compromised EL0 net driver **cannot redirect a
single byte of NIC DMA** — materially better than sDDF achieves without an IOMMU.

## Regions (sDDF §4.2.1 mapped onto HEQK)

| sDDF region | HEQK | EL0 grant | Notes |
|---|---|---|---|
| Device control | GEM MMIO / RTL BAR2 | `map_user_device` @ +0x2000 | Device-nGnRnE RW |
| Device metadata (HW rings) | `gem::RXRING.desc`, `rtl8111::RX.desc` | **`map_user_nc_ro`** @ +0x3000/+0x4000 | **read-only** (H4) |
| Driver metadata (class queues) | `DevQRegion`, one 4 KiB page | `map_user_nc` @ +0x5000 | RW — the new ABI |
| Data region (payloads) | `NetPool` | **NOT MAPPED** | sDDF §4.2.1: the driver never needs the data |

Both sides reach the queue page through **Normal-NC** aliases of the same frame
(HEQK's `NC_ALIAS_VA` GB257), so it is coherent with zero cache maintenance — HEQK
had independently converged on sDDF's mapping policy.

## The ABI (freeze this)

One 4 KiB page: 4 queues x 32 descriptors x 16 B. Head and tail on **separate
64-byte lines**. `capacity` is deliberately absent from shared memory (H1).

```rust
#[repr(C)] pub struct BufDesc { io_or_off: u64, len: u16, flags: u16, cookie: u32 } // 16 B
#[repr(C, align(64))] pub struct QHdr { head: AtomicU32, consumer_signalled: AtomicU32, _p0:[u32;14],
                                        tail: AtomicU32, producer_signalled: AtomicU32, _p1:[u32;14] } // 128 B
```

Queues: `RxFree`(kernel->driver), `RxActive`(**driver->kernel, hostile**),
`TxActive`(kernel->driver), `TxFree`(**driver->kernel, hostile**).
Indices are free-running `u32`, `slot = idx & 31` (structurally in-bounds even if
the index is attacker-chosen), occupancy = `tail.wrapping_sub(head)`.

## Ordering contract (Cortex-A76, Normal-NC) — validated

* publish = `STLR` (`Ordering::Release`); observe = `LDAR` (`Ordering::Acquire`).
  Architecturally sufficient on Normal-NC — **no DMB/DSB needed**.
* **NO read-modify-write ever** on this region (`LDXR/STXR`, LSE `CAS/LDADD`):
  exclusives on Normal-NC are not architecturally guaranteed. Strict SPSC needs none.
* **No FEAT_LSE2 on A76** => descriptors can tear => H3 copy-then-validate is
  mandatory, not stylistic.
* One `dc_civac` through the cacheable alias at init, then NC-only forever
  (the `gem.rs` mismatched-attributes fix).

## Hardware seam

`hal::NetDev` trait: `hw_rx_arm/hw_rx_status/hw_tx_arm/hw_tx_done/kick_tx/grants`.
Implemented by `GemDev`, `RtlDev`, and a pure-software `LoopDev` so P11 is
CI-gateable in QEMU. The same class code path over >=2 impls **is** the
interchangeability proof.

## Validation checklist (V1..V20 condensed)

Spatial: every access is `descs[idx & 31]` in a compile-time-sized region.
Temporal: kernel-private `own[]` table is the sole ownership authority.
Ordering: LDAR/STLR + snapshot-before-validate.
Liveness: every drain is bounded by a kernel-private constant; full => drop+count,
never block. Plus: `csdb` after bounds checks (Spectre-v1), reserved area never
read, signal flags advisory-only (liveness never safety), revoke must also unmap.

## Residual hole (document, don't hide)

The driver keeps RW on the MMIO page, so it can reprogram the ring base registers
and relocate the whole ring. Closing that needs a doorbell-only MMIO sub-page or a
kernel-mediated register-write syscall — tracked as **P11-R1**. Current mitigation
is the `iommu::fence` whole-bus ceiling.

## Sources

sDDF design doc (trustworthy.systems/projects/drivers), au-ts/sddf
`include/sddf/network/queue.h`, LionsOS (arXiv:2501.06234), and in-repo
`ZEROCOPY_IPC_RING.md`, `CAPABILITY_MODEL.md`, `HEQK_REMEDIATION_PLAN.md`.
