//! P11 — Device-class transport (the sDDF borrow), the hardened security core.
//!
//! DEVICE_CLASS_TRANSPORT.md is the frozen design; this is its QEMU-validatable
//! core. sDDF assumes drivers are TRUSTED; HEQK's threat model says an EL0 driver
//! is UNTRUSTED, so we take sDDF's SPSC structure and add the hardenings:
//!
//!  * H1 — queue geometry (`capacity`) lives ONLY in kernel-private memory
//!    (`QHandle::cap`), NEVER in the shared region. A forged capacity can't drive
//!    OOB indexing because `slot = idx & MASK` is *structurally* in-bounds.
//!  * H2 — the kernel keeps a PRIVATE buffer-ownership table (`NetClass::own`); a
//!    descriptor is accepted only if the kernel believes the driver owns that
//!    buffer in the expected role. sDDF's "a buffer is in at most one queue" is
//!    cooperative; here it is ENFORCED.
//!  * H3 — COPY-THEN-VALIDATE. Cortex-A76 is Armv8.2-A with no FEAT_LSE2, so a
//!    16-byte descriptor read is NOT single-copy-atomic and can TEAR. We snapshot
//!    the 16 bytes into kernel-private storage in ONE pass and then validate the
//!    COPY — never validate-then-reread.
//!
//! Ordering contract (Cortex-A76, Normal-NC): publish = STLR (`Release`), observe
//! = LDAR (`Acquire`). NO read-modify-write EVER on the shared region (LDXR/STXR
//! and LSE atomics are not architecturally guaranteed on Normal-NC; strict SPSC
//! needs none). A `csdb` follows every bounds check (Spectre-v1, V19). Per
//! ARCHITECTURE.md's single-core "Concurrency invariant" there is exactly one
//! hart, so the acquire/release pair is what carries a descriptor across the
//! EL1<->EL0 switch — the in-kernel stand-in driver of the P11 proof uses the raw
//! shared-memory protocol exactly as a hostile EL0 driver would.
//!
//! This generalizes `netq.rs` (P17): netq is per-slot-ownership and net-specific;
//! DevQ is the class-agnostic, head/tail SPSC transport that every device class
//! shares, with the ownership authority factored into a pluggable class validator
//! (`NetClass` here). netq.rs is unchanged — DevQ is additive.
//!
//! FOLLOW-UP (documented, not built here): the metal `GemDev`/`RtlDev` `NetDev`
//! impls + the read-only HW-ring grant (`map_user_nc_ro`, H4). This file proves the
//! SECURITY property — rejection of a hostile driver's forged descriptors — with an
//! in-kernel stand-in, with no hardware.

use core::sync::atomic::{AtomicU32, Ordering};

/// Descriptors per queue (power of two). `slot = idx & MASK` is therefore always
/// structurally in-bounds, even for an attacker-chosen index.
pub const NDESC: usize = 32;
pub const MASK: u32 = (NDESC as u32) - 1;
/// Queues per region: RxFree, RxActive, TxActive, TxFree.
pub const NQUEUES: usize = 4;

/// Queue identity within a region (index into the header/descriptor arrays).
/// RxActive and TxFree are the driver->kernel directions — the HOSTILE ones.
pub mod qid {
    pub const RX_FREE: usize = 0; // kernel -> driver
    pub const RX_ACTIVE: usize = 1; // driver -> kernel  (HOSTILE)
    pub const TX_ACTIVE: usize = 2; // kernel -> driver
    pub const TX_FREE: usize = 3; // driver -> kernel  (HOSTILE)
}

/// One buffer descriptor — 16 bytes, the frozen ABI (DEVICE_CLASS_TRANSPORT.md
/// §"The ABI"). `io_or_off` is a bus address OR a data-region offset; `cookie`
/// identifies the buffer to the kernel's ownership table. It lives in shared
/// memory and is therefore ENTIRELY attacker-controlled on the hostile queues.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BufDesc {
    pub io_or_off: u64,
    pub len: u16,
    pub flags: u16,
    pub cookie: u32,
}

impl BufDesc {
    pub const ZERO: BufDesc = BufDesc { io_or_off: 0, len: 0, flags: 0, cookie: 0 };
}

/// Queue header — head and tail deliberately on SEPARATE 64-byte cache lines (no
/// false sharing across the SPSC boundary). `capacity` is intentionally ABSENT
/// from shared memory (H1). The `*_signalled` words are advisory liveness hints
/// only — never a safety input.
#[repr(C, align(64))]
pub struct QHdr {
    pub head: AtomicU32,           // consumer advances this
    pub consumer_signalled: AtomicU32,
    _p0: [u32; 14],
    pub tail: AtomicU32,           // producer advances this
    pub producer_signalled: AtomicU32,
    _p1: [u32; 14],
}

impl QHdr {
    const fn new() -> Self {
        QHdr {
            head: AtomicU32::new(0),
            consumer_signalled: AtomicU32::new(0),
            _p0: [0; 14],
            tail: AtomicU32::new(0),
            producer_signalled: AtomicU32::new(0),
            _p1: [0; 14],
        }
    }
}

/// The shared region — one 4 KiB page, 4 queues x 32 descriptors x 16 B. Mapped
/// Normal-NC on both sides (`map_user_nc`) in production; a plain static here.
/// Both `hdr` and `desc` are `pub` on purpose: the P11 proof's in-kernel stand-in
/// driver scribbles them directly, exactly as an untrusted EL0 driver with a
/// Normal-NC grant would.
#[repr(C, align(4096))]
pub struct DevQRegion {
    pub hdr: [QHdr; NQUEUES],
    pub desc: [[BufDesc; NDESC]; NQUEUES],
    _pad: [u8; 4096 - NQUEUES * 128 - NQUEUES * NDESC * 16],
}

impl DevQRegion {
    pub const fn new() -> Self {
        const H: QHdr = QHdr::new();
        const ROW: [BufDesc; NDESC] = [BufDesc::ZERO; NDESC];
        DevQRegion {
            hdr: [H, H, H, H],
            desc: [ROW; NQUEUES],
            _pad: [0; 4096 - NQUEUES * 128 - NQUEUES * NDESC * 16],
        }
    }
    /// Reset one queue's indices (test/bring-up helper — the kernel owns geometry).
    pub fn reset(&self, q: usize) {
        self.hdr[q].head.store(0, Ordering::Release);
        self.hdr[q].tail.store(0, Ordering::Release);
    }
}

// --- Compile-time ABI freeze (H1/H3 depend on these exact sizes) --------------
const _: () = assert!(core::mem::size_of::<BufDesc>() == 16);
const _: () = assert!(core::mem::size_of::<QHdr>() == 128);
const _: () = assert!(core::mem::size_of::<DevQRegion>() == 4096);
const _: () = assert!(NDESC.is_power_of_two());

/// Which side the kernel plays on a queue (documents intent; the op itself is what
/// enforces producer-vs-consumer discipline).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Producer,
    Consumer,
}

/// KERNEL-PRIVATE queue handle (H1). `cap` — the geometry — is here and NEVER read
/// from shared memory. `cap` is never read from the region, so a driver cannot
/// forge it.
pub struct QHandle {
    pub cap: u32, // capacity — KERNEL-PRIVATE geometry (H1)
    pub q: usize, // which queue in the region
    pub producer: Side,
    pub last_seen_tail: u32, // advisory (liveness), never a safety input
}

impl QHandle {
    pub const fn producer(q: usize) -> Self {
        QHandle { cap: NDESC as u32, q, producer: Side::Producer, last_seen_tail: 0 }
    }
    pub const fn consumer(q: usize) -> Self {
        QHandle { cap: NDESC as u32, q, producer: Side::Consumer, last_seen_tail: 0 }
    }
}

/// A validation failure class, mapping to the frozen V-checks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    Index = 0,    // V2 — tail out of index range (occupancy > capacity)
    Offset = 1,   // V4 — io_or_off / cookie out of the data region
    Len = 2,      // V4 — len outside [MIN, BUFSZ]
    Flags = 3,    // V4 — unknown flag bits set
    NotOwned = 4, // V5 — kernel does not believe the driver owns this buffer
}
pub const V_COUNT: usize = 5;

/// Violation + liveness counters (kernel-private; single-core, so plain `u32`).
#[derive(Clone, Copy)]
pub struct DevQStats {
    pub viol: [u32; V_COUNT],
    pub accepted: u32,
    pub dropped_full: u32,
}

impl DevQStats {
    pub const fn new() -> Self {
        DevQStats { viol: [0; V_COUNT], accepted: 0, dropped_full: 0 }
    }
    pub fn total_violations(&self) -> u32 {
        self.viol.iter().copied().sum()
    }
    fn count(&mut self, v: Violation) {
        self.viol[v as usize] += 1;
    }
}

/// Consumption of Speculative Data Barrier — placed AFTER a bounds check so a
/// mispredicted path cannot speculatively use an out-of-range index (Spectre-v1,
/// V19). Encoded as a HINT, so it assembles on A72 (QEMU) and A76 (CM5) alike.
#[inline(always)]
fn csdb() {
    unsafe { core::arch::asm!("csdb", options(nomem, nostack, preserves_flags)) };
}

/// H3 — snapshot the 16-byte descriptor at `slot` into kernel-private storage in
/// ONE pass, returning the COPY. On A76 (no FEAT_LSE2) this read may TEAR; that is
/// exactly why we validate the returned copy and NEVER re-read the shared slot.
#[inline]
fn snapshot_desc(region: &DevQRegion, q: usize, slot: usize) -> BufDesc {
    // slot is `idx & MASK` at every call site -> structurally in-bounds.
    let p = core::ptr::addr_of!(region.desc[q][slot]);
    unsafe { core::ptr::read_volatile(p) }
}

/// PRODUCER op (SPSC). Publish `desc` if there is room. NEVER blocks: a full queue
/// increments `dropped_full` and returns false (backpressure, not a stall). The
/// producer owns `tail`; the write is a plain volatile store followed by an STLR
/// on `tail` — NO read-modify-write on the region.
pub fn enqueue(region: &DevQRegion, h: &QHandle, stats: &mut DevQStats, desc: &BufDesc) -> bool {
    debug_assert!(h.producer == Side::Producer);
    let hdr = &region.hdr[h.q];
    let tail = hdr.tail.load(Ordering::Relaxed); // producer's own index
    let head = hdr.head.load(Ordering::Acquire); // observe the consumer
    if tail.wrapping_sub(head) >= h.cap {
        stats.dropped_full += 1; // full -> drop + count, NEVER block
        return false;
    }
    let slot = (tail & MASK) as usize; // structurally in-bounds
    unsafe { core::ptr::write_volatile(core::ptr::addr_of!(region.desc[h.q][slot]) as *mut BufDesc, *desc) };
    hdr.tail.store(tail.wrapping_add(1), Ordering::Release); // publish (STLR)
    true
}

/// CONSUMER op (SPSC), hardened. Drain up to `min(budget, cap)` descriptors —
/// HARD-bounded by the kernel-private capacity so a forged tail can never make the
/// loop run long. For each descriptor: check V2 (index range) against the private
/// `cap`, `csdb`, H3-snapshot the slot, consume the slot (advance head) REGARDLESS
/// of the verdict (V6 — a rejected descriptor still consumes its slot so a hostile
/// driver cannot wedge the queue), then run the class `validate` on the COPY. A
/// forged tail (occupancy > cap) is counted once and the queue is resynced to
/// empty (head <- tail) so it stays usable without ever indexing with the forged
/// tail. Returns the number of accepted descriptors.
pub fn drain_checked<V>(
    region: &DevQRegion,
    h: &mut QHandle,
    budget: usize,
    stats: &mut DevQStats,
    mut validate: V,
) -> u32
where
    V: FnMut(&BufDesc) -> Result<(), Violation>,
{
    debug_assert!(h.producer == Side::Consumer);
    let hdr = &region.hdr[h.q];
    let bound = budget.min(h.cap as usize); // liveness: kernel-private hard bound
    let mut accepted = 0u32;
    for _ in 0..bound {
        let head = hdr.head.load(Ordering::Relaxed); // consumer's own index
        let tail = hdr.tail.load(Ordering::Acquire); // attacker-controlled on hostile queues
        let occ = tail.wrapping_sub(head);
        if occ == 0 {
            break; // genuinely empty
        }
        // V2 — an honest producer never has occupancy > capacity. A forged
        // `tail = head + huge` is caught HERE, against the kernel-private `cap`,
        // and never used to index anything.
        if occ > h.cap {
            stats.count(Violation::Index);
            hdr.head.store(tail, Ordering::Release); // resync to empty; queue stays usable
            break;
        }
        csdb(); // V19 — no speculation past the range check
        let slot = (head & MASK) as usize; // structurally in-bounds
        let snap = snapshot_desc(region, h.q, slot); // H3 copy
        // V6 — consume the slot regardless of the verdict.
        hdr.head.store(head.wrapping_add(1), Ordering::Release);
        h.last_seen_tail = tail;
        match validate(&snap) {
            Ok(()) => {
                stats.accepted += 1;
                accepted += 1;
            }
            Err(v) => stats.count(v),
        }
    }
    accepted
}

// ===========================================================================
// NET class — the ownership authority (H2) + the descriptor validator (V4/V5).
// ===========================================================================

/// Buffers in the net data region (one per RxActive slot).
pub const NET_NBUF: usize = NDESC;
/// Per-buffer payload capacity.
pub const NET_BUFSZ: usize = 2048;
/// Minimum accepted frame length (a bare Ethernet header).
pub const NET_MIN: usize = 14;
/// The only flag bits the net class understands (start/end of frame). Any other
/// bit set is an unknown-flags violation (V4).
pub const NET_FLAG_SOF: u16 = 1 << 0;
pub const NET_FLAG_EOF: u16 = 1 << 1;
pub const NET_KNOWN_FLAGS: u16 = NET_FLAG_SOF | NET_FLAG_EOF;

/// Kernel's belief about who owns a buffer (H2). The ownership table is the SOLE
/// authority; the descriptor's own fields never grant ownership.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BufState {
    KernelOwned, // the kernel holds it; the driver may NOT reference it
    DriverRx,    // handed to the driver to fill on the RX path
    DriverTx,    // handed to the driver to drain on the TX path
}

/// The net device class: a kernel-private ownership table over the data region.
pub struct NetClass {
    own: [BufState; NET_NBUF], // H2 — the sole ownership authority
    data_len: u64,             // size of the data region (offset upper bound)
}

impl NetClass {
    pub const fn new() -> Self {
        NetClass { own: [BufState::KernelOwned; NET_NBUF], data_len: (NET_NBUF * NET_BUFSZ) as u64 }
    }

    /// Kernel hands buffer `cookie` to the driver in role `role` (records it in the
    /// private table). Only buffers passed through here are ever `DriverRx`/`DriverTx`.
    pub fn hand_to_driver(&mut self, cookie: usize, role: BufState) {
        if cookie < NET_NBUF {
            self.own[cookie] = role;
        }
    }

    /// Reclaim a buffer to the kernel (after a validated drain).
    pub fn reclaim(&mut self, cookie: usize) {
        if cookie < NET_NBUF {
            self.own[cookie] = BufState::KernelOwned;
        }
    }

    pub fn owner(&self, cookie: usize) -> Option<BufState> {
        self.own.get(cookie).copied()
    }

    /// V4 + V5 validator, run on a KERNEL-PRIVATE COPY of the descriptor (H3).
    ///   V4: cookie < slots; io_or_off aligned + in the data region and matching
    ///       the cookie's buffer; len in [MIN, BUFSZ]; only known flag bits.
    ///   V5: the kernel's private table says the driver owns this buffer in the
    ///       EXPECTED role — else NotOwned (this is what catches a double-submit or
    ///       a buffer the driver was never given).
    pub fn check_from_driver(&self, d: &BufDesc, expect: BufState) -> Result<(), Violation> {
        // V4 — cookie must index a real buffer slot.
        let cookie = d.cookie as usize;
        if cookie >= NET_NBUF {
            return Err(Violation::Offset);
        }
        // V4 — offset aligned to a buffer, inside the region, and consistent with
        // the cookie (defense in depth: address and identity must agree).
        let off = d.io_or_off;
        let bufsz = NET_BUFSZ as u64;
        if off % bufsz != 0 || off >= self.data_len || off != (cookie as u64) * bufsz {
            return Err(Violation::Offset);
        }
        // V4 — length sane (0xFFFF and 0 both rejected here).
        let len = d.len as usize;
        if len < NET_MIN || len > NET_BUFSZ {
            return Err(Violation::Len);
        }
        // V4 — no unknown flag bits.
        if d.flags & !NET_KNOWN_FLAGS != 0 {
            return Err(Violation::Flags);
        }
        // V5 — ownership authority.
        if self.own[cookie] != expect {
            return Err(Violation::NotOwned);
        }
        Ok(())
    }
}

// ===========================================================================
// LoopDev — a pure-software producer/consumer so the transport is exercised with
// NO hardware (the CI-gateable stand-in NetDev of DEVICE_CLASS_TRANSPORT.md).
// ===========================================================================

/// Exercise the honest transport end to end on a single queue with a trivial
/// always-accept validator: fill the ring to capacity (proving full => drop+count,
/// never block), drain it (proving the SPSC release/acquire carries every
/// descriptor), then push past the wrap point and drain again. Returns
/// (produced_ok, dropped_full, consumed). A correct transport yields
/// produced_ok == consumed and dropped_full >= 1.
pub struct LoopDev;

impl LoopDev {
    pub fn selftest(region: &DevQRegion) -> (u32, u32, u32) {
        region.reset(qid::RX_FREE);
        let mut pstats = DevQStats::new();
        let mut cstats = DevQStats::new();
        let ph = QHandle::producer(qid::RX_FREE);
        let mut ch = QHandle::consumer(qid::RX_FREE);
        let mut produced_ok = 0u32;
        // Overfill by 8 to force the full-path (NDESC + 8 attempts).
        for i in 0..(NDESC + 8) {
            let d = BufDesc {
                io_or_off: (i % NET_NBUF) as u64 * NET_BUFSZ as u64,
                len: NET_MIN as u16,
                flags: NET_FLAG_SOF | NET_FLAG_EOF,
                cookie: (i % NET_NBUF) as u32,
            };
            if enqueue(region, &ph, &mut pstats, &d) {
                produced_ok += 1;
            }
        }
        // Drain the full ring, then enqueue 8 more (wrapping the indices) + drain.
        let mut consumed = drain_checked(region, &mut ch, 64, &mut cstats, |_d| Ok(()));
        for i in 0..8usize {
            let d = BufDesc {
                io_or_off: (i % NET_NBUF) as u64 * NET_BUFSZ as u64,
                len: NET_MIN as u16,
                flags: NET_FLAG_SOF | NET_FLAG_EOF,
                cookie: (i % NET_NBUF) as u32,
            };
            if enqueue(region, &ph, &mut pstats, &d) {
                produced_ok += 1;
            }
        }
        consumed += drain_checked(region, &mut ch, 64, &mut cstats, |_d| Ok(()));
        (produced_ok, pstats.dropped_full, consumed)
    }
}
