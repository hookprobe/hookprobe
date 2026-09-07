//! RP1 GEM (Cadence MACB) Gigabit Ethernet — polled RX bring-up (CM5/BCM2712).
//!
//! In-kernel first-light driver: reach the MAC, bring the PHY out of reset, arm
//! an RX descriptor ring, and poll for one real frame — then the Packet Engine
//! gives it an IDS verdict. Register map + descriptor format confirmed vs the
//! Linux `macb` driver; addresses + DMA translation from THIS board's DTB. See
//! RP1_GEM_BRINGUP.md.
//!
//! DMA note (critical): the GEM is a bus master behind the RP1 PCIe endpoint, so
//! the addresses it DMAs to are RP1/PCIe *bus* addresses, not CPU-physical. The
//! board's dma-ranges make bus = cpu_phys + 0x10_0000_0000, which is >4 GB, so
//! 64-bit (16-byte) descriptors + GEM_ADDR64 are mandatory even for low RAM.
//! Caches are ON (P7a), and this DMA path is NOT cache-coherent, so we clean
//! descriptors/buffers before handing to HW and invalidate before reading.

use core::ptr::{read_volatile, write_volatile};

// --- RP1 block bases (bare-metal window, = CPU 0x1f.. with 0x1f->0x1c) --------
const GEM: usize = 0x1C00_100000; // ethernet@100000, 16 KiB
const ETH_CFG: usize = 0x1C00_104000; // RP1 GEM glue (link status, clkgen)
const RP1_CLK: usize = 0x1C00_018000; // RP1 clock controller
// RP1 GPIO banks are 0x4000 apart: IO_BANKn @ 0xd0000+n*0x4000, SYS_RIOn @
// 0xe0000+n*0x4000, PADS_BANKn @ 0xf0000+n*0x4000. ETH_RST_N = GPIO32 = bank1
// index 4. RIO has atomic aliases: +0x1000 XOR, +0x2000 SET, +0x3000 CLR.
// (window base 0x1C_0000_0000 + RP1 internal offset; note the 10-hex-digit form)
const RP1_IO_BANK1: usize = 0x1C_000D_4000;
const RP1_RIO1: usize = 0x1C_000E_4000;
const RP1_PADS1: usize = 0x1C_000F_4000;
const ETH_RST_IDX: usize = 4; // GPIO32 within bank1
const RIO_SET: usize = 0x2000; // atomic set-bits alias
const RIO_CLR: usize = 0x3000; // atomic clear-bits alias

// --- GEM register offsets (Cadence MACB / GEM) --------------------------------
const NCR: usize = 0x000; // Network Control
const NCFGR: usize = 0x004; // Network Config
const NSR: usize = 0x008; // Network Status
const DMACFG: usize = 0x010; // DMA Config (GEM)
const TSR: usize = 0x014; // Transmit Status
// TSR bits (Cadence GEM). ALL of these except TGO are write-1-to-clear, and the
// error ones HALT the transmitter until cleared — which is why they must be handled
// rather than defined and ignored (they were, until the 2026-08-20 metal run).
const TSR_UBR: u32 = 1 << 0; // Used Bit Read: HW read a descriptor with USED=1 -> TX STOPS
const TSR_COL: u32 = 1 << 1; // collision occurred
const TSR_RLE: u32 = 1 << 2; // retry limit exceeded -> TX STOPS
const TSR_TGO: u32 = 1 << 3; // transmit go (status, read-only — never W1C this)
const TSR_TFC: u32 = 1 << 4; // frame corruption / buffers exhausted mid-frame -> TX STOPS
const TSR_TXCOMP: u32 = 1 << 5; // transmit complete
const TSR_UND: u32 = 1 << 6; // transmit underrun -> TX STOPS
const TSR_HRESP: u32 = 1 << 7; // HRESP not OK -> TX STOPS
/// Every W1C bit (TGO excluded: it is read-only status, not a latch).
const TSR_W1C: u32 = TSR_UBR | TSR_COL | TSR_RLE | TSR_TFC | TSR_TXCOMP | TSR_UND | TSR_HRESP;
/// The subset that HALTS the transmitter — seeing any of these means TX will stay
/// dead for every subsequent frame until it is cleared AND the transmitter restarted.
const TSR_HALTING: u32 = TSR_UBR | TSR_RLE | TSR_TFC | TSR_UND | TSR_HRESP;

/// TX completion poll budget, in iterations.
///
/// WAS 500_000 (~50 ms). That is ~500x longer than any observed success and it was
/// throttling the whole sensor: the datapath is SYNCHRONOUS, so every frame's RX
/// processing waits on that frame's TX completion. Metal, 2026-08-21: a 2000-frame burst
/// gave seen=221 with tx_fail=88 — 40% of frames hit the FULL budget, i.e. ~4.4 s of a
/// 14 s window parked in TX timeouts. The RX ring then overflows (rsr=BNA|OVR) not because
/// it is too shallow but because the loop drains it at ~15 frames/s.
///
/// MEASURED completion: ~364-391 spins on a first kick, ~2460 with a 2000-spin retrigger
/// interval (i.e. ~400 spins after the retrigger). With RETRIGGER_SPINS=512 the worst
/// legitimate case is ~900. 8192 leaves ~9x margin over that while capping a genuinely
/// stuck transmit at ~0.8 ms instead of 50 ms — a ~60x reduction in the worst-case stall.
///
/// This does NOT make TX more reliable; it stops an unrecoverable frame from starving RX.
/// The architecturally correct fix is to stop blocking RX on TX completion at all
/// (asynchronous completion reaping), which is a contract change and its own piece of work.
const TX_POLL_BUDGET: u32 = 8192;

/// How often (in poll iterations) to re-issue a possibly-dropped TSTART.
///
/// Tuned against MEASURED latency, not guessed: boot 11 showed a first-kick success
/// completing in 364-391 spins and a dropped-kick frame completing at ~2460 — i.e. ~400
/// spins after the retrigger fired at 2000. So ~400 spins is the real transmission time,
/// and a 2000 interval made every dropped kick wait ~5x longer than necessary. 512 catches
/// a dropped TSTART almost immediately with comfortable margin over the observed ~400.
///
/// SHARED between tx_frame and tx_diag_burst ON PURPOSE: they were briefly allowed to
/// drift (production 512, diagnostic hardcoded 2000), which made the diagnostic report
/// spin counts for a configuration that was no longer shipping. A diagnostic that does
/// not mirror the code it measures produces wrong conclusions.
pub const RETRIGGER_SPINS: u32 = 512;

/// Round-robin TX slot cursor. Advancing per frame keeps the controller's prefetch
/// pointed at a descriptor OTHER than the one currently in flight.
static mut TX_SLOT: usize = 0;

/// Last TX status that accompanied a failure, latched for diagnostics (0 = none since
/// the last take). Lets the sensor report WHY a PASS frame was not forwarded instead of
/// reporting an anonymous timeout.
static mut LAST_TX_ERR: u32 = 0;

/// Read-and-clear the last TX error status (see `LAST_TX_ERR`).
pub fn tx_err_take() -> u32 {
    unsafe {
        let v = core::ptr::read_volatile(core::ptr::addr_of!(LAST_TX_ERR));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(LAST_TX_ERR), 0);
        v
    }
}
const RBQP: usize = 0x018; // RX buffer queue base (low)
const TBQP: usize = 0x01c; // TX buffer queue base (low)
const RSR: usize = 0x020; // Receive Status
const ISR: usize = 0x024; // Interrupt Status (read-to-clear on macb)
const IER: usize = 0x028; // Interrupt Enable
const IDR: usize = 0x02c; // Interrupt Disable (mask all)
const INT_RCOMP: u32 = 1 << 1; // receive-complete interrupt
const TBQPH: usize = 0x4c8; // TX buffer queue base (high, 64-bit)
const RBQPH: usize = 0x4d4; // RX buffer queue base (high, 64-bit)

// NCR bits
const NCR_RE: u32 = 1 << 2; // receive enable
const NCR_TE: u32 = 1 << 3; // transmit enable
const NCR_MPE: u32 = 1 << 4; // MDIO enable
const NCR_TSTART: u32 = 1 << 9; // start transmission (kick the TX DMA)
// NCFGR bits
const NCFGR_FD: u32 = 1 << 1; // full duplex
const NCFGR_CAF: u32 = 1 << 4; // copy-all-frames (promiscuous)
const NCFGR_GBE: u32 = 1 << 10; // gigabit mode (DDR RX sampling) — REQUIRED for 1G RX
const NCFGR_MDC_DIV128: u32 = 6 << 18; // GEM_CLK: pclk/128 (~1.5 MHz MDC @200 MHz)
// Data Bus Width (NCFGR bits[22:21]): 0=32b, 1=64b, 2=128b. The RP1 GEM is a
// 128-bit AXI4 master — macb_init_hw() sets NCFGR |= macb_dbw() = DBW128. Leaving
// it 0 (32-bit) is a bus-width mismatch the narrow 16-byte descriptors tolerated
// but the wide extended (24-byte) descriptor DMA + status writeback does not.
const NCFGR_DBW128: u32 = 2 << 21;
// DMACFG bits
const DMACFG_ADDR64: u32 = 1 << 30;
// RP1's GEM_GXL is FULL store-and-forward ONLY (partial SF not implemented), which
// requires the packet-buffer memory-size fields to select the full addressable
// space — else HW receives the frame + sets USED but writes a ZERO ctrl/status
// word (no length). Both Linux macb_configure_dma() and U-Boot set these
// unconditionally. Omitting them is the RP1 GEM descriptor-length ("w1=0") bug.
const DMACFG_RXBMS: u32 = 3 << 8; // RX packet buffer: full configured size
const DMACFG_TXPBMS: u32 = 1 << 10; // TX packet buffer: full size
// RX/TX Buffer-Descriptor EXTENDED mode (DMACFG bit28/bit29). The RP1 GEM has PTP
// hardware-timestamping capability (HW_DMA_CAP_PTP), and — proven by booting the
// mainline `macb` driver on this exact silicon (DHCP lease obtained, rx_length_
// errors=0) — it only writes the RX status/length word (word1) when extended-BD
// mode is on AND the descriptors are the WIDE 6-word (24-byte) format: base
// {addr,ctrl} + 64b {addrh,resvd} + ptp {ts_1,ts_2}. Linux's macb_configure_dma()
// sets RXEXT|TXEXT whenever HW_DMA_CAP_PTP. Setting these bits with a 16-byte ring
// (our earlier attempt) corrupts the ring — the descriptor MUST be 6 words wide
// (see DESC_WORDS / RxRing below). THIS is the real w1=0 fix.
const DMACFG_RXEXT: u32 = 1 << 28;
const DMACFG_TXEXT: u32 = 1 << 29;
// RX descriptor word0 flags (in the low bits of the buffer address)
const RXD_USED: u32 = 1 << 0; // 0 = HW-owned; HW sets 1 after writing a frame
const RXD_WRAP: u32 = 1 << 1; // last descriptor
// RX descriptor word1 (ctrl/status) fields
const RXD_FRMLEN: u32 = 0x3fff; // GEM: 14-bit frame length (RP1 sets JUMBO caps)
// TX descriptor word1 (ctrl) bits
const TXD_USED: u32 = 1 << 31; // HW sets after transmit; SW clears to arm
const TXD_WRAP: u32 = 1 << 30; // last descriptor in the ring
const TXD_LAST: u32 = 1 << 15; // last buffer of the frame
// RSR bits
const RSR_BNA: u32 = 1 << 0; // buffer not available (DMA target unreachable)
const RSR_REC: u32 = 1 << 1; // frame received

/// The DMA bus-address offset: GEM bus address = CPU physical + this.
const DMA_BUS_OFFSET: u64 = 0x10_0000_0000;

/// Non-Cacheable alias base (mmu_cm5 GB257 → physical GB0). Descriptor rings live
/// physically in low RAM but are accessed ONLY through this NC window, so the CPU
/// never caches them and the GEM's status writeback (word1) is always coherent —
/// matching Linux's dma_alloc_coherent. `nc_desc(phys) = phys + NC_VA`.
const NC_VA: usize = crate::mmu_cm5::NC_ALIAS_VA;
#[inline]
fn nc_desc(phys: usize) -> *mut u32 {
    (phys + NC_VA) as *mut u32
}

/// BCM2712 PCIe RC2 (the RP1 x4 link) register base — a SoC block, directly
/// CPU-addressable (not through the RP1 window). We program its INBOUND window
/// so RP1/GEM DMA can reach system RAM (firmware only set the outbound window).
const PCIE_RC: usize = 0x10_0012_0000;

/// Program the brcmstb (BCM7712 path) inbound DMA window: map PCIe bus
/// 0x10_0000_0000 (64 GiB) → system RAM 0x0, via RC_BAR1 + UBUS_BAR1 remap +
/// SCB_ACCESS_EN. Confirmed vs Linux pcie-brcmstb.c. Returns the pre-write
/// (RC_BAR1_LO, UBUS_REMAP_LO) so we can see if firmware already set it.
pub fn pcie_inbound_window() -> (u32, u32) {
    let rd = |off: usize| unsafe { read_volatile((PCIE_RC + off) as *const u32) };
    let wr = |off: usize, v: u32| unsafe { write_volatile((PCIE_RC + off) as *mut u32, v) };
    let bar1_lo_before = rd(0x402c);
    let ubus_lo_before = rd(0x40ac);
    // SCB_ACCESS_EN (global inbound gate) — RMW.
    wr(0x4008, rd(0x4008) | 0x1000);
    // RC_BAR1: bus addr 0x10_0000_0000, size field 0x15 (2^36 = 64 GiB). HI first.
    wr(0x4030, 0x0000_0010);
    wr(0x402c, 0x0000_0015);
    // UBUS_BAR1 remap: system target 0x0 + ACCESS_EN(bit0). HI first, LO arms it.
    wr(0x40b0, 0x0000_0000);
    wr(0x40ac, 0x0000_0001);
    // Defensive: make a stray inbound error return data, not wedge the bridge.
    wr(0x40a4, rd(0x40a4) | (1 << 13) | (1 << 19));
    wr(0x4170, 0xffff_ffff);
    (bar1_lo_before, ubus_lo_before)
}

/// RX ring depth.
///
/// Was 8 — BELOW the minimum the reference driver for this controller declares. Linux
/// drivers/net/ethernet/cadence/macb_main.c:58-59:
///
///     #define DEFAULT_RX_RING_SIZE 512 /* must be power of 2 */
///     #define MIN_RX_RING_SIZE      64
///
/// Measured consequence of 8 (2026-08-20, isolated DUT link): a deterministic 2000-frame
/// burst was seen as only 214 frames — ~89% lost. At 1 Gbps a 2000-frame burst arrives in
/// about a millisecond, so a ring of 8 overflows almost immediately while software is
/// still processing the first descriptor. This is burst ABSORPTION, distinct from
/// steady-state processing rate: a deeper ring lets the controller keep queueing while the
/// EL0 driver excursion + verdict + forward completes for earlier frames.
///
/// 64 = Linux's stated MINIMUM. Deliberately not larger yet: the EL0 RX driver is granted
/// exactly ONE 4 KiB Normal-NC page onto the descriptor ring (map_user_nc at
/// USER_VA_BASE+0x3000), and 64 x 24 B = 1536 B fits with room to spare, whereas 256 would
/// need 6144 B and a second page — a mapping change that should be its own step.
///
/// ⚠️ The depth is ALSO hardcoded in the EL0 scan stub (`gem_rx_stub`, syscall.s:
/// `cmp x2, #64`). Both must change together.
/// ⚠️ REVERTED TO 8 — DO NOT RAISE THIS WITHOUT READING THIS COMMENT.
///
/// The reference driver for this controller declares a MINIMUM of 64
/// (Linux drivers/net/ethernet/cadence/macb_main.c:58-59: DEFAULT_RX_RING_SIZE 512,
/// MIN_RX_RING_SIZE 64), so 8 is objectively too small and burst absorption is poor:
/// a deterministic 2000-frame burst on an isolated link is seen as ~214 frames.
///
/// BUT RAISING IT TO 64 MADE THINGS WORSE, MEASURED ON METAL (2026-08-20):
/// the same 2000-frame burst was seen as only **16** frames, and then RX STOPPED
/// ENTIRELY — `seen` froze at 16 while `empty` kept incrementing, i.e. the EL0 scan
/// stub reported no further frames. That is a FUNCTIONAL REGRESSION, not a slower path.
/// The EL0 stub's scan bound was raised in lockstep (syscall.s `cmp x2, #64`), so the
/// cause is something else — candidates NOT yet distinguished:
///   * descriptor recycle/index bookkeeping that only holds for a small ring;
///   * RXRING growing 16 KiB -> 128 KiB and crossing a DMA-reachability or IOMMU-fence
///     boundary (the P14 fence ceiling), or the buffer pool no longer being where the
///     controller can write it;
///   * cache maintenance over a much larger buffer pool (dc_civac over 128 KiB).
///
/// The next attempt MUST be instrumented first: the heartbeat now reports RSR, so
/// `rsr` bit0 BNA (buffers not available) vs bit2 OVR (overrun) vs clean will
/// distinguish "ring overflowed" from "controller could not write the buffers at all".
/// Do not raise NRX again until that reading exists.
/// RX ring depth. Currently BISECTING — see the measurement history below.
///
/// TARGET CONFIRMED BY HARDWARE (2026-08-20): after a deterministic 2000-frame burst on
/// the isolated DUT link the heartbeat reported **rsr=0x07 = BNA | REC | OVR** — the
/// controller ran out of descriptors (BNA, buffers-not-available) AND overran (OVR). Ring
/// exhaustion is therefore the real limit, measured rather than inferred. The reference
/// driver agrees: Linux drivers/net/ethernet/cadence/macb_main.c:58-59 declares
/// DEFAULT_RX_RING_SIZE 512 and MIN_RX_RING_SIZE 64, so 8 was always far too small.
///
/// MEASUREMENT HISTORY (2000-frame burst, isolated link, `seen` counted):
///     NRX=8   -> 214 seen, rsr=0x07 (BNA|OVR)   baseline, functional
///     NRX=64  -> 16 seen, then RX STOPPED DEAD   REGRESSION (`seen` froze, `empty` rose)
///     NRX=16  -> (this step)
///
/// The 64 regression was NOT a descriptor-handling bug: WRAP is set correctly on the last
/// descriptor, rx_init loops over NRX cleanly, and the EL0 scan bound was raised in
/// lockstep. Leading hypothesis is a LAYOUT collision — RXRING grows 16 KiB -> 128 KiB at
/// 64, shifting all of .bss, and this codebase has been bitten by exactly that before (the
/// M5.4 commit records a latent stack overflow "benign only by luck until M5.4's .bss
/// shifted the tripwire into the blast zone"), with hardcoded physical addresses also in
/// play (the 0x980000 cap-test base, EL0 code/stack pages).
///
/// 16 is the bisection step: RXRING grows only 16 KiB -> 32 KiB. If 16 works, the failure
/// is SIZE-dependent (layout) and the ceiling can be raised carefully toward 64. If 16
/// ALSO breaks, the failure is triggered by NRX != 8 itself and the bug is in code that
/// assumes the small ring.
///
/// ⚠️ The depth is ALSO hardcoded in the EL0 scan stub (`gem_rx_stub`, syscall.s
/// `cmp x2, #N`). Both must change together.
/// RX ring depth = 128.
///
/// MEASUREMENT HISTORY (2000-frame burst on the isolated DUT link, `seen` counted):
///     NRX=8                    -> 213, rsr=0x07 (BNA|OVR)
///     NRX=64, one stub patched -> 16, RX DEAD   (the two-stub bug, not the depth)
///     NRX=16, one stub patched -> 16, RX DEAD   (same bug — this is what disproved the
///                                                ".bss layout collision" theory)
///     NRX=16, BOTH stubs       -> 221, rsr=0x07  (+4% only)
///     NRX=16 + TX budget 8192  -> 221            (TX stalls were NOT the throttle)
///     NRX=128                  -> (this step)
///
/// WHAT THE NUMBERS ACTUALLY SAY: the generator pushes 2000 frames in ~50 ms; the sensor
/// drained ~220 of them in that window, i.e. a drain rate around 4400 frames/s. The other
/// ~1780 were dropped AT THE WIRE by hardware because the ring had nowhere to put them —
/// which is why 14 further seconds of idle never raised the count. Buffering IS the limit,
/// but 16 was never going to matter: at 4400/s drain and a 50 ms burst you need a ring of
/// order 1800 to absorb it. Linux's DEFAULT_RX_RING_SIZE of 512
/// (drivers/net/ethernet/cadence/macb_main.c:58) is the considered number.
///
/// 128 is the CEILING IMPOSED BY THE EL0 GRANT, not a tuning choice: the isolated EL0 RX
/// driver is given exactly ONE 4 KiB Normal-NC page onto the descriptor ring
/// (map_user_nc at USER_VA_BASE+0x3000), and 4096/24 = 170 descriptors fit. 128 is the
/// largest power of two under that. Going beyond needs a multi-page EL0 grant, which is a
/// mapping change and its own piece of work.
///
/// ⚠️ THERE ARE TWO EL0 RX SCAN STUBS (gem_rx_stub AND gem_ids_stub — the PROD sensor loop
/// uses the latter). BOTH hardcode this depth. Updating only one silently strands every
/// descriptor past the stale bound: the ring fills, they are never recycled, BNA fires and
/// RX DIES. That cost two metal cycles; see syscall.s.
const NRX: usize = 128;
const RXBUF: usize = 2048;
// Extended-BD descriptor = 6 u32 words / 24 bytes: {addr_lo, ctrl} + {addr_hi,
// resvd} (DMA64) + {ts_1, ts_2} (PTP). RXEXT/TXEXT in DMACFG make the GEM use this
// wide format; the ring stride MUST match or the status writeback lands off. word0
// = addr_lo(+USED/WRAP), word1 = ctrl/status(len,SOF,EOF), word2 = addr_hi.
const DESC_W: usize = 6;
const DESC_SZ: usize = DESC_W * 4; // 24 bytes

/// RX ring + buffers, page-aligned, in kernel RAM (identity-mapped: VA == PA).
#[repr(C, align(4096))]
struct RxRing {
    desc: [[u32; DESC_W]; NRX], // 24-byte extended DMA64+PTP descriptors
    buf: [[u8; RXBUF]; NRX],
}
static mut RXRING: RxRing = RxRing {
    desc: [[0; DESC_W]; NRX],
    buf: [[0; RXBUF]; NRX],
};

/// TX ring depth. MUST be >= 2 — a one-entry ring is architecturally invalid on this
/// controller, proven by instrumentation on 2026-08-20 (`[P8-txdiag]`):
///
///   seq ok  w1_armed    tsr_pre tsr_post  w1_final     spins
///     2 OK  0x4000803c  0x0021  0x0021    0xc000803c     481
///     3 --  0x4000803c  0x0021  0x0021    0x4000803c  200000
///
/// The software-visible state at TSTART is BYTE-IDENTICAL on the succeeding and failing
/// frames — same armed descriptor, same TSR, and TSTART never changes TSR on either. The
/// differing variable is therefore INTERNAL to the GEM. With one descriptor carrying
/// WRAP, the controller's prefetch of "the next descriptor" ALIASES the descriptor it
/// just completed, so it holds a cached copy reading USED=1, rejects that frame, re-reads,
/// and the FOLLOWING kick sees a valid copy — a one-deep prefetch over a self-wrapping
/// ring gives exactly one frame of lag, i.e. the phase-locked 50% loss that was measured.
///
/// With NTX >= 2 the prefetch targets a DIFFERENT descriptor and cannot alias the active
/// one. Note this is about ring GEOMETRY, not about pipelining depth: the TX path here is
/// still fully synchronous (arm one, kick, poll to completion).
const NTX: usize = 2;
const TXBUF: usize = 2048;

/// TX ring + buffer, page-aligned, in kernel RAM (identity-mapped: VA == PA).
#[repr(C, align(4096))]
struct TxRing {
    desc: [[u32; DESC_W]; NTX], // 24-byte extended DMA64+PTP descriptors
    buf: [[u8; TXBUF]; NTX],
}
static mut TXRING: TxRing = TxRing {
    desc: [[0; DESC_W]; NTX],
    buf: [[0; TXBUF]; NTX],
};

#[inline]
fn r(base: usize, off: usize) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}
#[inline]
fn w(base: usize, off: usize, v: u32) {
    unsafe { write_volatile((base + off) as *mut u32, v) };
}
/// Invalidate (only) a range — use BEFORE reading device-DMA'd data so the CPU
/// fetches fresh from DRAM. NOT clean+invalidate: the "clean" would push the
/// CPU's stale copy back over the device's write.
#[inline]
fn dc_ivac(addr: usize, len: usize) {
    let mut a = addr & !63;
    let end = addr + len;
    while a < end {
        unsafe { core::arch::asm!("dc ivac, {}", in(reg) a) };
        a += 64;
    }
    unsafe { core::arch::asm!("dsb sy") };
}
/// Clean (only) a range — use AFTER writing descriptors so the device sees them.
#[inline]
fn dc_cvac(addr: usize, len: usize) {
    let mut a = addr & !63;
    let end = addr + len;
    while a < end {
        unsafe { core::arch::asm!("dc cvac, {}", in(reg) a) };
        a += 64;
    }
    unsafe { core::arch::asm!("dsb sy") };
}
/// Clean+Invalidate a range — used ONCE on the descriptor region before we switch
/// to Non-Cacheable-alias access, so no stale cacheable copy of those bytes
/// survives (avoids a mismatched-attributes hazard).
#[inline]
fn dc_civac(addr: usize, len: usize) {
    let mut a = addr & !63;
    let end = addr + len;
    while a < end {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) a) };
        a += 64;
    }
    unsafe { core::arch::asm!("dsb sy") };
}

const MAN: usize = 0x034; // PHY maintenance (MDIO)
const NSR_IDLE: u32 = 1 << 2; // MDIO idle (transaction complete)

/// Read PHY register `reg` at MDIO address `phy` via the GEM MAN register.
/// Requires NCR.MPE set + a valid MDC divider (done in rx_init). Returns the
/// 16-bit value, or 0xFFFF if the bus never idles / PHY absent (held in reset).
pub fn phy_read(phy: u32, reg: u32) -> u16 {
    // MAN: SOF=01, op=10(read), phy, reg, TA=10.
    let cmd = (0b01 << 30) | (0b10 << 28) | ((phy & 0x1f) << 23) | ((reg & 0x1f) << 18) | (0b10 << 16);
    w(GEM, MAN, cmd);
    let mut spins = 0u32;
    while r(GEM, NSR) & NSR_IDLE == 0 {
        spins += 1;
        if spins > 1_000_000 {
            return 0xFFFF;
        }
    }
    (r(GEM, MAN) & 0xffff) as u16
}

/// Write a PHY register via MAN.
pub fn phy_write(phy: u32, reg: u32, val: u16) {
    let cmd = (0b01 << 30) | (0b01 << 28) | ((phy & 0x1f) << 23) | ((reg & 0x1f) << 18) | (0b10 << 16) | (val as u32);
    w(GEM, MAN, cmd);
    let mut s = 0u32;
    while r(GEM, NSR) & NSR_IDLE == 0 {
        s += 1;
        if s > 1_000_000 {
            return;
        }
    }
}

/// Kick auto-negotiation and read PHY link state. Returns (bmcr, bmsr, anlpar)
/// where BMSR bit2 = link up (read twice to clear the latch), ANLPAR = partner
/// abilities. Enables MPE first. `phy` = MDIO address.
pub fn phy_link(phy: u32) -> (u16, u16, u16) {
    w(GEM, NCFGR, NCFGR_MDC_DIV128);
    w(GEM, NCR, NCR_MPE);
    // BMCR reg0: enable + restart auto-negotiation (bit12 | bit9).
    phy_write(phy, 0, 1 << 12 | 1 << 9);
    // Give autoneg time.
    for _ in 0..800_000_000u32 {
        core::hint::spin_loop();
    }
    let bmcr = phy_read(phy, 0);
    let _ = phy_read(phy, 1); // first read clears the latched-low link bit
    let bmsr = phy_read(phy, 1);
    let anlpar = phy_read(phy, 5);
    (bmcr, bmsr, anlpar)
}

/// Configure the BCM54210 RGMII internal delays for "rgmii-id" (RX+TX delay in
/// the PHY). RX via AUXCTL (reg 0x18, shadow MISC 0x07, RGMII_SKEW_EN bit8); TX
/// via SHD (reg 0x1c, shadow 0x03 = CLK_CTL, GTXCLK_EN bit9). RMW-preserving,
/// exactly as Linux bcm54xx_config_clock_delay().
pub fn phy_rgmii_id(phy: u32) {
    // RX delay: read MISC shadow, OR in WREN|SKEW_EN, write back (bits[2:0]=0x07).
    phy_write(phy, 0x18, 0x7007); // select MISC shadow for read
    let misc = phy_read(phy, 0x18) as u32;
    phy_write(phy, 0x18, (0x07 | misc | 0x8000 | 0x0100) as u16);
    // TX delay: read CLK_CTL shadow 0x03, OR in GTXCLK_EN, write back.
    phy_write(phy, 0x1c, 0x03 << 10); // select shadow 3 for read (WRITE bit clear)
    let shd = (phy_read(phy, 0x1c) & 0x3ff) as u32;
    phy_write(phy, 0x1c, (0x8000 | (0x03 << 10) | ((shd | 0x0200) & 0x3ff)) as u16);
}

/// Configure the BCM54210PE LEDs to green=link/speed, amber=activity — matching phy1
/// (RTL8111H) and the schematic wiring of the Waveshare CM5-DUAL-ETH-MINI. Returns
/// (LED-Selector-1 shadow0x0D before, after, PHY-status reg1) for verification.
///
/// Schematic-verified: PHY LED1 output -> CM5 Ethernet_nLED3 -> GREEN; PHY LED3 output
/// -> Ethernet_nLED2 -> AMBER. broadcom.c LEDS1 (shadow 0x0D): LED1 source = bits[3:0],
/// LED3 source = bits[7:4]; sources: LINKSPD1=0x0, ACTIVITYLED=0x3. So green(LED1)=
/// LINKSPD1(0x0), amber(LED3)=ACTIVITYLED(0x3) => shadow 0x0D = 0x0030. Shadow write via
/// reg 0x1C: bit15=WRITE | (shadow<<10) | (data & 0x3FF).
pub fn phy0_led_config(phy: u32) -> (u16, u16, u16) {
    w(GEM, NCR, NCR_MPE);
    // read current LED Selector 1 (shadow 0x0D).
    phy_write(phy, 0x1c, 0x0d << 10);
    let before = phy_read(phy, 0x1c) & 0x3ff;
    // green(LED1)=LINKSPD1(0x0), amber(LED3)=ACTIVITYLED(0x3) -> 0x030.
    phy_write(phy, 0x1c, 0x8000 | (0x0d << 10) | 0x030);
    // read back.
    phy_write(phy, 0x1c, 0x0d << 10);
    let after = phy_read(phy, 0x1c) & 0x3ff;
    (before, after, phy_read(phy, 1))
}

/// Read the RP1 eth_cfg STATUS: RGMII link (bit0), speed (bits2:1), duplex (bit3).
pub fn link_status() -> u32 {
    r(ETH_CFG, 0x04)
}

/// Diagnostics: PHY ID at MDIO addr 0 and 1 (reg2/reg3), plus the ETH_RST_N pin
/// level (RIO_IN bit4 of bank1) so we can see if the reset GPIO actually drove.
/// Enables MPE + MDC first. Returns (id_at0, id_at1, rst_pin_level).
pub fn diagnose() -> (u32, u32, u32) {
    w(GEM, NCFGR, NCFGR_MDC_DIV128);
    w(GEM, NCR, NCR_MPE);
    let id0 = ((phy_read(0, 2) as u32) << 16) | phy_read(0, 3) as u32;
    let id1 = ((phy_read(1, 2) as u32) << 16) | phy_read(1, 3) as u32;
    // RIO_IN (0x08) bit ETH_RST_IDX = current level of the reset pin.
    let rin = unsafe { read_volatile((RP1_RIO1 + 0x08) as *const u32) };
    let rst_level = (rin >> ETH_RST_IDX) & 1;
    (id0, id1, rst_level)
}

/// Probe: confirm the GEM block is reachable and report link. Non-destructive.
/// Returns (ncfgr, dmacfg_or_id, eth_cfg_status).
pub fn probe() -> (u32, u32, u32) {
    (r(GEM, NCFGR), r(GEM, DMACFG), link_status())
}

/// Deassert the PHY reset (ETH_RST_N = RP1 GPIO32, active-low): funcsel the pad
/// to software GPIO (RIO), enable its output driver, drive low (assert), hold
/// ≥5 ms, then high (release). Correct bank-1 addresses.
fn phy_reset() {
    let bit: u32 = 1 << ETH_RST_IDX;
    unsafe {
        // Pad: clear OD (output-disable, bit7), set IE (input-enable, bit6).
        let pad = (RP1_PADS1 + 4 + 4 * ETH_RST_IDX) as *mut u32;
        let v = read_volatile(pad);
        write_volatile(pad, (v & !0x80) | 0x40);
        // Route the pad to software GPIO: IO_BANK1 GPIO32_CTRL funcsel = 5.
        let ctrl = (RP1_IO_BANK1 + 8 * ETH_RST_IDX + 4) as *mut u32;
        write_volatile(ctrl, (read_volatile(ctrl) & !0x1f) | 5);
        // Normal read-modify-write on RIO OUT(0x00)/OE(0x04) (not atomic alias).
        let out = RP1_RIO1 as *mut u32;
        let oe = (RP1_RIO1 + 0x04) as *mut u32;
        write_volatile(oe, read_volatile(oe) | bit); // output enable
        write_volatile(out, read_volatile(out) & !bit); // LOW = reset asserted
        for _ in 0..3_000_000u32 {
            core::hint::spin_loop();
        } // ≥5 ms
        write_volatile(out, read_volatile(out) | bit); // HIGH = reset released
        let _ = (RIO_SET, RIO_CLR);
    }
}

/// Dump the ETH_RST_N GPIO register state (CTRL, PAD, RIO OUT/OE/IN) so we can
/// see exactly what landed. Returns (ctrl, pad, rio_out, rio_oe, rio_in).
pub fn gpio_dump() -> (u32, u32, u32, u32, u32) {
    unsafe {
        (
            read_volatile((RP1_IO_BANK1 + 8 * ETH_RST_IDX + 4) as *const u32),
            read_volatile((RP1_PADS1 + 4 + 4 * ETH_RST_IDX) as *const u32),
            read_volatile(RP1_RIO1 as *const u32),
            read_volatile((RP1_RIO1 + 0x04) as *const u32),
            read_volatile((RP1_RIO1 + 0x08) as *const u32),
        )
    }
}

/// Wait up to ~`ms` for the RGMII link (eth_cfg.STATUS bit0). Returns the final
/// status word. Gives the PHY time to auto-negotiate after reset-release.
pub fn wait_link(ms: u32) -> u32 {
    let mut st = 0;
    for _ in 0..ms {
        st = link_status();
        if st & 1 != 0 {
            return st;
        }
        for _ in 0..400_000u32 {
            core::hint::spin_loop();
        } // ~1 ms
    }
    st
}

/// Enable the RP1 clk_eth (tx clock). pclk/hclk (clk_sys) is always-on.
fn enable_clocks() {
    // CLK_ETH_CTRL = 0x064; ENABLE = bit11. Leave DIV/SEL as firmware set them.
    let ctrl = RP1_CLK + 0x064;
    unsafe {
        let v = read_volatile(ctrl as *const u32) | (1 << 11);
        write_volatile(ctrl as *mut u32, v);
    }
}

/// Bring up polled RX end to end. Returns (ring, phy_auxstatus, eth_cfg_status).
/// Configures the PHY (reset, rgmii-id delays, autoneg), reads the negotiated
/// speed, sets the MAC to gigabit if needed, forces the RP1 speed override, and
/// arms the RX ring.
pub fn rx_init() -> (usize, u16, u32) {
    enable_clocks();
    // Open the PCIe inbound DMA window BEFORE the GEM starts DMAing.
    pcie_inbound_window();
    phy_reset();

    // Bring MDIO up (MPE + MDC), set the rgmii-id delays, then kick auto-neg.
    w(GEM, NCFGR, NCFGR_MDC_DIV128);
    w(GEM, NCR, NCR_MPE);
    phy_rgmii_id(0);
    phy_write(0, 0, (1 << 12) | (1 << 9)); // BMCR: autoneg enable + restart
    // Wait for link (PHY BMSR reg1 bit2) up to ~3 s.
    let mut auxstat = 0u16;
    for _ in 0..3000 {
        if phy_read(0, 1) & (1 << 2) != 0 {
            auxstat = phy_read(0, 0x19); // aux status: speed in bits[10:8]
            break;
        }
        for _ in 0..400_000u32 {
            core::hint::spin_loop();
        }
    }
    let speed_code = (auxstat >> 8) & 0x7; // 7=1000/full, 5=100/full, ...
    let is_gig = speed_code >= 6; // 110/111 = 1000
    // RP1 eth_cfg CLKGEN (0x14): force MAC-side speed (BCM54210 sends no RGMII
    // in-band status). SPEED_OVERRIDE_EN=bit3, SPEED_OVERRIDE[1:0]: 2=1G,1=100.
    let clkgen = r(ETH_CFG, 0x14);
    let spd_ovr = if is_gig { 2 } else { 1 };
    w(ETH_CFG, 0x14, (clkgen & !0x3) | (1 << 3) | spd_ovr);

    // Descriptor ring physical base (for RBQP); == addr_of!(RXRING.desc[0]).
    let ring = unsafe { core::ptr::addr_of!(RXRING.desc) as usize };
    // Drop any cacheable copy of the descriptor region, then build the ring ONLY
    // through the Non-Cacheable alias (coherent with the GEM — no clean-clobber of
    // the status word). Buffers stay cacheable (invalidated before reading).
    dc_civac(ring, NRX * DESC_SZ);
    for i in 0..NRX {
        let bufpa = unsafe { core::ptr::addr_of!(RXRING.buf[i]) as u64 };
        let bus = bufpa + DMA_BUS_OFFSET;
        let mut w0 = (bus as u32) & !0x3; // low addr; USED=0 (hw-owned)
        if i == NRX - 1 {
            w0 |= RXD_WRAP;
        }
        let dphys = unsafe { core::ptr::addr_of!(RXRING.desc[i]) as usize };
        let d = nc_desc(dphys); // Non-Cacheable alias pointer
        unsafe {
            write_volatile(d.add(0), w0);
            write_volatile(d.add(1), 0); // ctrl/status — GEM fills len/SOF/EOF on RX
            write_volatile(d.add(2), (bus >> 32) as u32); // addr high (= 0x10)
            write_volatile(d.add(3), 0); // resvd
            write_volatile(d.add(4), 0); // ts_1 (PTP)
            write_volatile(d.add(5), 0); // ts_2 (PTP)
        }
    }
    unsafe { core::arch::asm!("dsb sy") }; // ensure the ring is in DRAM before RE

    // AUDIT M-6: the RX *payload* buffers live in kernel .bss and are Normal-WB
    // cacheable. The boot stub zeroes .bss with caches on, so they can hold DIRTY
    // lines. This driver only ever INVALIDATES, and only at read time over the
    // copied range (dc_ivac in poll_rx). If a dirty line is evicted after the GEM
    // has DMA'd a frame into that address, the eviction writes stale bytes OVER the
    // received data — silent, timing-dependent frame corruption which the IDS then
    // fail-closes to DROP, i.e. packet loss that masquerades as a detection.
    // Clean+invalidate the whole pool once, before reception is enabled.
    let bufpool = unsafe { core::ptr::addr_of!(RXRING.buf) as usize };
    dc_civac(bufpool, NRX * RXBUF);

    // Quiesce, mask IRQs (polled), configure DMA64 + RX buffer size, ring base.
    w(GEM, NCR, 0);
    w(GEM, IDR, 0xffff_ffff);
    let _ = r(GEM, RSR);
    w(GEM, RSR, RSR_BNA | RSR_REC); // clear sticky status
    let rxbs = (RXBUF / 64) as u32; // RX buffer size in 64-byte units
    // ADDR64 + RX/TX extended-BD mode (6-word descriptors, required for the word1
    // status writeback on this PTP-capable GEM) + full-SF buffer sizing + INCR16
    // burst => 0x70200710. Matches the mainline macb config that works on metal.
    w(GEM, DMACFG,
        DMACFG_ADDR64 | DMACFG_RXEXT | DMACFG_TXEXT
            | DMACFG_RXBMS | DMACFG_TXPBMS | (rxbs << 16) | 0x10);
    let ringbus = ring as u64 + DMA_BUS_OFFSET;
    w(GEM, RBQPH, (ringbus >> 32) as u32); // high FIRST
    w(GEM, RBQP, ringbus as u32);
    // MAC: promiscuous + broadcast, MDC divider, full-duplex, and GIGABIT mode
    // if the link negotiated 1G (required — 1000BASE-T RX is DDR-sampled).
    let mut ncfgr = NCFGR_CAF | NCFGR_MDC_DIV128 | NCFGR_FD | NCFGR_DBW128;
    if is_gig {
        ncfgr |= NCFGR_GBE;
    }
    w(GEM, NCFGR, ncfgr);
    w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE);
    (ring, auxstat, link_status())
}

/// Poll the RX ring once. Returns Some((len, w0, w1, w2, w3)) with the raw
/// descriptor words for diagnosis, and fills `out` with the frame. None = none.
pub fn poll_rx(out: &mut [u8]) -> Option<(usize, u32, u32, u32, u32)> {
    // Rotating consumer index across calls.
    static mut IDX: usize = 0;
    let i = unsafe { IDX % NRX };
    let dphys = unsafe { core::ptr::addr_of!(RXRING.desc[i]) as usize };
    let dptr = nc_desc(dphys); // Non-Cacheable alias — coherent with the GEM, no cache maintenance
    let w0 = unsafe { read_volatile(dptr.add(0)) };
    if w0 & RXD_USED == 0 {
        return None; // still HW-owned: no frame yet
    }
    // NC memory is coherent: once USED is seen, the status word (word1: len/SOF/EOF)
    // written by the GEM before it set USED is already visible — no spin, no clobber.
    let ctrl = unsafe { read_volatile(dptr.add(1)) };
    let w2 = unsafe { read_volatile(dptr.add(2)) };
    let w3 = unsafe { read_volatile(dptr.add(3)) };
    let desc_len = (ctrl & RXD_FRMLEN) as usize;
    let bufpa = unsafe { core::ptr::addr_of!(RXRING.buf[i]) as usize };
    // Copy exactly the GEM-reported frame length. L-13/XC-16: when the descriptor
    // reports NO length (word1==0), do NOT fabricate a full-buffer frame — that fed
    // the IDS ~1600 bytes of mostly-stale buffer as if it were a real frame,
    // manufacturing a false detection. Copy nothing and report len=0; the slot is
    // still recycled below, and the caller treats len==0 as "no valid frame". The
    // authoritative IDS path uses rx_desc_status() (M-7), which also rejects len==0.
    let copy_n = desc_len.min(out.len()).min(RXBUF);
    dc_ivac(bufpa, copy_n); // buffers stay cacheable — invalidate before reading DMA'd data
    for k in 0..copy_n {
        out[k] = unsafe { read_volatile((bufpa + k) as *const u8) };
    }
    let len = copy_n;
    // Recycle: clear USED in word0 through the NC alias — the write goes straight
    // to DRAM (coherent), so there is no cache clean and no false-sharing clobber
    // of a neighbour's status. Leave word1 for the GEM to overwrite next RX.
    unsafe {
        let bus = bufpa as u64 + DMA_BUS_OFFSET;
        let mut nw0 = (bus as u32) & !0x3; // USED=0 (hw-owned)
        if i == NRX - 1 {
            nw0 |= RXD_WRAP;
        }
        write_volatile(dptr.add(0), nw0);
        core::arch::asm!("dsb sy"); // ensure the re-arm reaches DRAM before the GEM re-reads
        IDX = IDX.wrapping_add(1);
    }
    Some((len, w0, ctrl, w2, w3))
}

/// Arm the TX ring. NCR.TE is already enabled by rx_init; here we point the GEM
/// at our single-descriptor TX ring and mark it USED (idle, nothing to send) so
/// a stray TSTART can't transmit garbage. Call once after rx_init.
pub fn tx_init() {
    let dphys = unsafe { core::ptr::addr_of!(TXRING.desc) as usize }; // physical ring base (for TBQP)
    dc_civac(dphys, NTX * DESC_SZ); // drop cacheable copies; access via NC alias hereafter
    // Arm EVERY descriptor as idle (USED=1 = software owns it, nothing to send), each
    // pointing at its OWN buffer, with WRAP on the LAST one only. WRAP marks the end of
    // the ring; putting it on any earlier descriptor truncates the ring to that length.
    for i in 0..NTX {
        let bus = unsafe { core::ptr::addr_of!(TXRING.buf[i]) as u64 } + DMA_BUS_OFFSET;
        let d = nc_desc(dphys + i * DESC_SZ);
        let wrap = if i == NTX - 1 { TXD_WRAP } else { 0 };
        unsafe {
            write_volatile(d.add(0), bus as u32);
            write_volatile(d.add(1), TXD_USED | wrap); // idle; WRAP only on the last slot
            write_volatile(d.add(2), (bus >> 32) as u32); // addr high (= 0x10)
            write_volatile(d.add(3), 0); // resvd
            write_volatile(d.add(4), 0); // ts_1 (PTP)
            write_volatile(d.add(5), 0); // ts_2 (PTP)
        }
    }
    unsafe {
        core::arch::asm!("dsb sy");
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TX_SLOT), 0);
    }
    let ringbus = dphys as u64 + DMA_BUS_OFFSET;
    w(GEM, TBQPH, (ringbus >> 32) as u32); // high FIRST
    w(GEM, TBQP, ringbus as u32);
}

/// Transmit one frame out end0 (synchronous: kick TSTART, poll TX completion).
/// Returns Some(tx_ctrl) — the completed descriptor status word (USED set) — or
/// None on timeout. This is the IPS enforcement primitive: the datapath calls it
/// ONLY for frames whose BPF verdict is PASS; a DROP frame is simply never sent,
/// so the verdict now acts on the wire instead of only being logged.
pub fn tx_frame(bytes: &[u8]) -> Option<u32> {
    let n = bytes.len().min(TXBUF);
    // Advance the slot BEFORE arming so consecutive frames use different descriptors —
    // the whole point of NTX>=2 (see the NTX doc comment).
    let slot = unsafe {
        let sl = core::ptr::read_volatile(core::ptr::addr_of!(TX_SLOT));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TX_SLOT), (sl + 1) % NTX);
        sl
    };
    let bufpa = unsafe {
        let tr = &mut *core::ptr::addr_of_mut!(TXRING);
        for k in 0..n {
            tr.buf[slot][k] = bytes[k];
        }
        tr.buf[slot].as_ptr() as usize
    };
    dc_cvac(bufpa, n); // TX buffer is cacheable — clean so the device reads the frame
    let dphys = unsafe { core::ptr::addr_of!(TXRING.desc) as usize } + slot * DESC_SZ;
    let d = nc_desc(dphys); // NC alias — coherent, no descriptor cache maintenance
    let bus = bufpa as u64 + DMA_BUS_OFFSET;
    let wrap = if slot == NTX - 1 { TXD_WRAP } else { 0 };
    unsafe {
        write_volatile(d.add(0), bus as u32); // word0 addr_lo
        write_volatile(d.add(2), (bus >> 32) as u32); // word2 addr_hi
        // word1: length | LAST | (WRAP only on the last slot), USED=0 — hand the
        // descriptor to HW. The GEM auto-pads to the 60B minimum and appends the FCS.
        write_volatile(d.add(1), (n as u32 & RXD_FRMLEN) | TXD_LAST | wrap);
        core::arch::asm!("dsb sy"); // ensure the armed descriptor is in DRAM before TSTART
    }
    // Clear any status latched by the PREVIOUS frame before kicking. TSR error bits are
    // sticky and halting: leaving one set means this transmit — and every one after it —
    // silently never completes. The 2026-08-20 CM5 run showed ~7-9% of PASS frames
    // failing in CLUSTERS, which is the signature of a latched halt rather than a
    // per-frame probability: TX stops, a run of frames times out, something incidentally
    // restarts it, then a clean stretch (48 consecutive successes were observed).
    let pre = r(GEM, TSR);
    if pre & TSR_W1C != 0 {
        w(GEM, TSR, pre & TSR_W1C); // W1C — never write TSR_TGO (read-only status)
    }
    // RECOVER HERE — AFTER the descriptor is armed, BEFORE the kick. Ordering is the
    // whole point, and two metal runs proved it:
    //
    // With NTX=1 the GEM finishes a frame, advances into the (now idle, USED=1)
    // descriptor, latches UBR and HALTS. That happens after EVERY transmit — depth alone
    // would not change it, because tx_frame arms exactly ONE descriptor and waits, so the
    // controller always advances into an unarmed slot whatever the ring size.
    //
    // Restarting at the wrong moment does not help:
    //   * restart AFTER COMPLETION (34122ea) re-enabled TE while the descriptor still
    //     read USED=1, so the engine immediately re-latched UBR and halted again before
    //     the next frame — burst measured 100/200, last_tsr=0x08;
    //   * NO restart at all (93dcbfd) left the halt standing, so the next frame's TSTART
    //     hit a dead engine and only its TIMEOUT recovered — burst measured 100/200,
    //     last_tsr=0x01.
    // Same 50% alternation from opposite policies, one root cause.
    //
    // Here the descriptor is ALREADY armed (USED=0, real work present), so bringing TE
    // back up gives the controller something to find instead of an idle slot to re-halt
    // on. RE stays up throughout: a TX-side recovery must never interrupt RX, which is
    // the detection path.
    if pre & TSR_HALTING != 0 {
        w(GEM, NCR, NCR_RE | NCR_MPE);
        unsafe { core::arch::asm!("dsb sy") };
        w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE);
    }
    // KICK, THEN RETRIGGER WHILE POLLING.
    //
    // Grounded in the reference driver for this exact controller — Linux
    // drivers/net/ethernet/cadence/macb_main.c:2517:
    //
    //     /* TSTART write might get dropped, so make the IRQ retrigger a buffer read */
    //     if (macb_readl(bp, TSR) & MACB_BIT(TGO))
    //             queue->tx_pending = 1;
    //     macb_writel(bp, NCR, macb_readl(bp, NCR) | MACB_BIT(TSTART));
    //
    // A TSTART write CAN BE SILENTLY DROPPED by the hardware. Linux expects this: it
    // notes the condition via TSR.TGO (transmitter still going) and has the TCOMP/TXUBR
    // IRQ retrigger the queue (macb_main.c:2058), where macb_tx_restart() re-reads TBQP,
    // compares the controller's consumer position against the software head, and
    // RE-ISSUES TSTART if the controller has not caught up (macb_main.c:1834-1843).
    //
    // heqk kicked exactly once and then polled for ~50 ms. A dropped kick therefore
    // produced a frame that never started, a full-budget timeout, and a reported failure
    // — while the NEXT frame's kick (by then the engine has settled) succeeded. That is
    // the deterministic 50% alternation, and it is frame-sequential, which is why it
    // appeared identically at NTX=1 and NTX=2.
    //
    // This path has no interrupts, so the synchronous equivalent of Linux's IRQ
    // retrigger is to re-issue TSTART periodically while waiting.
    //
    // ⚠️ DO NOT convert these NCR writes to a read-modify-write (NCR |= TSTART) even
    // though that is what macb does. It was tried and it BROKE TRANSMISSION COMPLETELY:
    // the burst went 0 sent / 200 FAILED with TSR reading 0x0000 on every frame — no
    // TXCOMP, no UBR, no TGO, i.e. the transmitter was not running AT ALL. NCR readback
    // is not trustworthy on this integration (TSTART is self-clearing, and the readback
    // did not carry TE), so `readback | TSTART` left TE CLEAR and disabled the
    // transmitter. The explicit write below guarantees RE|TE|MPE are set every time.

    w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE | NCR_TSTART); // kick the TX DMA
    // Poll for completion: HW sets USED (bit31) in word1 when the frame is out.
    let mut spins = 0u32;
    loop {
        if spins != 0 && spins % RETRIGGER_SPINS == 0 {
            // The kick may have been dropped (see above). Re-issue it; this is a no-op
            // for the controller if the frame is already in flight. Explicit write, not
            // a read-modify-write — see the NCR readback warning above.
            w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE | NCR_TSTART);
        }
        let ctrl = unsafe { read_volatile(d.add(1)) };
        if ctrl & TXD_USED != 0 {
            // Completed. Clear the latched status so it cannot accumulate into the next
            // frame's `pre` read and be mistaken for a fresh error.
            let post = r(GEM, TSR);
            if post & TSR_W1C != 0 {
                w(GEM, TSR, post & TSR_W1C);
            }
            // UBR IS EXPECTED HERE, EVERY TIME, AND IS NOT AN ERROR. This ring has one
            // descriptor with TXD_WRAP, so the moment a frame goes out the GEM wraps back
            // to it, reads USED=1 and latches TSR.UBR. That happens on ANY ring depth the
            // instant the TX queue drains — Linux's macb driver treats TXUBR as routine
            // and simply clears it. Clearing the latch (above) is the whole job here.
            //
            // DO NOT RESTART THE TRANSMITTER ON THIS PATH. A previous revision bounced TE
            // here whenever a halting bit was latched, and the deterministic burst caught
            // what sparse live traffic hid: 200 back-to-back frames gave EXACTLY
            // 100 sent / 100 FAILED — 50.0%, an alternating pattern, not a rate. The
            // bounce broke the very NEXT transmit: frame N completes -> UBR -> bounce TE
            // -> frame N+1's TSTART lands on a just-toggled engine and times out (~50 ms,
            // clean TSR because we had already cleared it) -> the TIMEOUT path bounces TE
            // again -> frame N+2 succeeds -> repeat. Each "recovery" cost the next frame.
            //
            // It looked harmless on live traffic (boot 3: 3.5%, no UBR reported) only
            // because frames there are far enough apart for the engine to settle. The
            // timeout path below still restarts, which is correct: THERE we have positive
            // evidence of a genuine stall (no forward progress for the full poll budget),
            // rather than a routine queue-drain latch.
            return Some(ctrl);
        }
        spins += 1;
        if spins >= TX_POLL_BUDGET {
            // Timed out. Record WHY, then RECOVER: clear the latched status and bounce
            // the transmit enable so a halted TX engine does not take every subsequent
            // frame down with it. Without this the failure is self-perpetuating.
            let err = r(GEM, TSR);
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(LAST_TX_ERR),
                    if err == 0 { TSR_TGO } else { err }, // 0 => "timeout, TSR clean"
                );
            }
            if err & TSR_W1C != 0 {
                w(GEM, TSR, err & TSR_W1C);
            }
            if err & TSR_HALTING != 0 {
                // TE low then high restarts the transmitter (RE is left up so RX — the
                // detection path — is never interrupted by a TX-side recovery).
                w(GEM, NCR, NCR_RE | NCR_MPE);
                unsafe { core::arch::asm!("dsb sy") };
                w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE);
            }
            return None;
        }
    }
}

/// Deterministic TX burst — send `n` minimal frames back-to-back and report
/// `(sent_ok, failed, last_tsr)`.
///
/// WHY: the tx_fail rate was previously only measurable against whatever happened to be
/// on the wire, and that link goes idle for 45 s at a stretch — every rate estimate off
/// it was drawn from a few dozen frames and moved wildly (20% -> 9% -> 2% -> 9% across
/// successive windows of the same boot). A fixed-size burst makes the measurement
/// independent of traffic, so a fix can actually be shown to work.
///
/// The frame is a minimal broadcast Ethernet frame with an unregistered EtherType, so it
/// is inert on the segment (no IP, no ARP semantics, nothing will answer it).
pub fn tx_burst_selftest(n: u32) -> (u32, u32, u32) {
    let mut frame = [0u8; 60];
    frame[0..6].copy_from_slice(&[0xff; 6]); // broadcast dst
    frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // locally-administered src
    frame[12] = 0x88; // EtherType 0x88b5 = IEEE 802.1 local experimental (inert)
    frame[13] = 0xb5;
    let (mut ok, mut bad) = (0u32, 0u32);
    for i in 0..n {
        frame[14] = (i & 0xff) as u8; // vary the payload so it is not a constant frame
        if tx_frame(&frame).is_some() {
            ok += 1;
        } else {
            bad += 1;
        }
    }
    (ok, bad, tx_err_take())
}

/// Phase-5 instrumentation: one TX attempt's full hardware state, captured at the
/// points that distinguish the competing failure hypotheses.
///
/// This exists because three "fixes" were applied to this path without ever observing
/// what the hardware actually did between frames. Every field is a raw register or
/// descriptor read — no interpretation.
#[derive(Clone, Copy)]
pub struct TxDiag {
    pub seq: u32,
    /// TSR as found on entry (i.e. whatever the PREVIOUS frame left behind).
    pub tsr_entry: u32,
    /// Descriptor word1 as found on entry, BEFORE we arm it. Tells us whether the
    /// previous frame's completion writeback (USED=1) is actually visible.
    pub w1_entry: u32,
    /// Descriptor word1 read back immediately after arming (expect USED=0).
    pub w1_armed: u32,
    /// TSR immediately before the TSTART write.
    pub tsr_prekick: u32,
    /// TSR immediately after the TSTART write — if the controller was halted and the
    /// kick was rejected, this is where it shows.
    pub tsr_postkick: u32,
    /// Descriptor word1 immediately after TSTART (before polling).
    pub w1_postkick: u32,
    /// Spins actually consumed (== budget on timeout).
    pub spins: u32,
    pub w1_final: u32,
    pub tsr_final: u32,
    pub ok: bool,
}

impl TxDiag {
    const fn zero() -> Self {
        TxDiag {
            seq: 0, tsr_entry: 0, w1_entry: 0, w1_armed: 0, tsr_prekick: 0,
            tsr_postkick: 0, w1_postkick: 0, spins: 0, w1_final: 0, tsr_final: 0,
            ok: false,
        }
    }
}

/// Instrumented TX burst. MIRRORS `tx_frame`'s exact sequence — if `tx_frame` changes,
/// change this with it — but snapshots hardware state at each transition instead of
/// only reporting the outcome. Deliberately performs NO recovery of any kind, so the
/// UNMODIFIED failure mechanism is what gets recorded.
///
/// `budget` is intentionally small (the production path uses 500k): a failing frame is
/// identified by "did not complete within a generous window", and a short budget keeps
/// the whole diagnostic bounded on a boot path.
pub fn tx_diag_burst(out: &mut [TxDiag], budget: u32) {
    let mut frame = [0u8; 60];
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame[12] = 0x88;
    frame[13] = 0xb5;

    let ringbase = unsafe { core::ptr::addr_of!(TXRING.desc) as usize };

    for i in 0..out.len() {
        let mut rec = TxDiag::zero();
        rec.seq = i as u32;
        frame[14] = (i & 0xff) as u8;

        // MIRROR tx_frame's slot rotation — a diagnostic pinned to one descriptor would
        // measure a ring geometry the production path no longer uses.
        let slot = unsafe {
            let sl = core::ptr::read_volatile(core::ptr::addr_of!(TX_SLOT));
            core::ptr::write_volatile(core::ptr::addr_of_mut!(TX_SLOT), (sl + 1) % NTX);
            sl
        };
        let d = nc_desc(ringbase + slot * DESC_SZ);

        // -- state as the PREVIOUS use of THIS slot left it ----------------------
        rec.tsr_entry = r(GEM, TSR);
        rec.w1_entry = unsafe { read_volatile(d.add(1)) };

        // -- arm (identical to tx_frame) ----------------------------------------
        let bufpa = unsafe {
            let tr = &mut *core::ptr::addr_of_mut!(TXRING);
            tr.buf[slot][..60].copy_from_slice(&frame);
            tr.buf[slot].as_ptr() as usize
        };
        dc_cvac(bufpa, 60);
        let bus = bufpa as u64 + DMA_BUS_OFFSET;
        let wrap = if slot == NTX - 1 { TXD_WRAP } else { 0 };
        unsafe {
            write_volatile(d.add(0), bus as u32);
            write_volatile(d.add(2), (bus >> 32) as u32);
            write_volatile(d.add(1), (60u32 & RXD_FRMLEN) | TXD_LAST | wrap);
            core::arch::asm!("dsb sy");
        }
        rec.w1_armed = unsafe { read_volatile(d.add(1)) };

        // -- kick. NO TSR clear, NO restart: record the raw mechanism. ----------
        rec.tsr_prekick = r(GEM, TSR);
        // Mirror tx_frame: EXPLICIT kick (NOT read-modify-write — NCR readback is not
        // trustworthy here; see the warning in tx_frame).
        w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE | NCR_TSTART);
        rec.tsr_postkick = r(GEM, TSR);
        rec.w1_postkick = unsafe { read_volatile(d.add(1)) };

        // -- poll ---------------------------------------------------------------
        let mut spins = 0u32;
        loop {
            // Mirror tx_frame: retrigger a possibly-dropped TSTART while polling.
            if spins != 0 && spins % RETRIGGER_SPINS == 0 {
                w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE | NCR_TSTART);
            }
            let ctrl = unsafe { read_volatile(d.add(1)) };
            if ctrl & TXD_USED != 0 {
                rec.ok = true;
                break;
            }
            spins += 1;
            if spins >= budget {
                break;
            }
        }
        rec.spins = spins;
        rec.w1_final = unsafe { read_volatile(d.add(1)) };
        rec.tsr_final = r(GEM, TSR);
        out[i] = rec;
    }
}

/// Current Receive Status register (for diagnostics: BNA/REC/overrun).
pub fn rsr() -> u32 {
    r(GEM, RSR)
}

/// DRV-1: dump the RP1 MIP (MSI-X) config region read-only, then ENABLE the ETH
/// RX-complete source, mirroring Linux drivers/mfd/rp1.c EXACTLY (not a guess):
///   msix_cfg_regs = bar_start + RP1_PCIE_APBS_BASE (0x108000) -> heqk 0x1C_0010_8000
///   MSIX_CFG(x)   = 0x8 + 4*x ;  RP1_INT_ETH = 6 -> 0x20
///   REG_RW=0x000, REG_SET=0x800 (write-1-to-set), INTSTATL=0x108
///   a LEVEL-HIGH source (the eth node's type) enables with ENABLE(b0) | IACK_EN(b3)
///
/// The enable is a pure CONFIG write — it carries NO DMA target address, so unlike a
/// PCIe MSI-X *table* write it cannot scribble memory; worst case is that no interrupt
/// fires (the PCIe MSI-X table was not set up by firmware) and the path stays silent.
/// Dumps the region before + reads MSIX_CFG(6) and INTSTATL back after. Returns the
/// read-back MSIX_CFG(6).
#[cfg(feature = "mipdump")]
pub fn rx_msix_setup() -> u32 {
    const MIP: usize = 0x1C_0010_8000; // bar(0x1C_0000_0000) + APBS 0x108000
    const REG_RW: usize = 0x000;
    const REG_SET: usize = 0x800;
    const CFG6: usize = 0x8 + 4 * 6; // MSIX_CFG(RP1_INT_ETH=6) = 0x20
    const INTSTATL: usize = 0x108;
    const ENABLE: u32 = 1 << 0;
    const IACK_EN: u32 = 1 << 3;
    crate::_print(format_args!(" [DRV1] RP1 MIP MSIX_CFG region @ {:#x} (read-only first):\n", MIP));
    for row in 0..2 {
        let base = MIP + REG_RW + row * 0x20;
        let r = |o: usize| -> u32 { unsafe { read_volatile((base + o) as *const u32) } };
        crate::_print(format_args!("   {:#08x}: {:08x} {:08x} {:08x} {:08x}  {:08x} {:08x} {:08x} {:08x}\n",
            base, r(0x00), r(0x04), r(0x08), r(0x0c), r(0x10), r(0x14), r(0x18), r(0x1c)));
    }
    unsafe {
        let pre = read_volatile((MIP + REG_RW + CFG6) as *const u32);
        let stat_pre = read_volatile((MIP + INTSTATL) as *const u32);
        write_volatile((MIP + REG_SET + CFG6) as *mut u32, ENABLE | IACK_EN);
        core::arch::asm!("dsb sy");
        let post = read_volatile((MIP + REG_RW + CFG6) as *const u32);
        crate::_print(format_args!(" [DRV1] MSIX_CFG(6) enable: pre={:#010x} -> post={:#010x} (want ENABLE|IACK_EN=0x9); INTSTATL pre={:#010x}\n",
            pre, post, stat_pre));
        // READ-ONLY: dump the brcmstb RC MSI controller (pcie-brcmstb.c) to disambiguate
        // the delivery model. If BAR_CONFIG_LO/HI + DATA_CONFIG are programmed, the RP1
        // uses the RC's CONSOLIDATED MSI demux (model a: one SoC IRQ + INTR2 status 0x4500),
        // NOT a dedicated per-source SPI 134 (model b, which heqk's handler assumes). All
        // reads of the RC block heqk already writes (PCIE_RC = 0x10_0012_0000). No writes.
        let rc = |off: usize| -> u32 { read_volatile((PCIE_RC + off) as *const u32) };
        crate::_print(format_args!(" [DRV1] RC MSI: BAR_CFG_LO(0x4044)={:#010x} HI(0x4048)={:#010x} DATA_CFG(0x404c)={:#010x} INTR2_STAT(0x4500)={:#010x}\n",
            rc(0x4044), rc(0x4048), rc(0x404c), rc(0x4500)));
        crate::_print(format_args!(" [DRV1] RC MSI: INTR2_MASK_STAT(0x450c)={:#010x} (model: nonzero BAR_CFG => RC-demux (a); zero => dedicated mip SPI (b))\n",
            rc(0x450c)));
        post
    }
}

/// DRV-1 ROOT-CAUSE FIX (metal 2026-09-08, from the RPi brcmstb driver): heqk's config
/// reads of the RP1 endpoint returned 0xffffffff because firmware set up the RC's OUTBOUND
/// MMIO windows (so GEM MMIO works — it routes by address) but never ENUMERATED the bus:
/// the RC bridge's secondary/subordinate bus-number registers are still 0/0, so a config
/// request to bus 1 is an Unsupported Request, surfaced as all-ones by the firmware-set
/// AXI_READ_ERROR_DATA=0xffffffff. Program the standard PCI-bridge registers in the RC's
/// OWN config space (root-bus access = PCIE_RC + reg directly, no EXT_CFG) so bus 1 falls
/// inside [secondary,subordinate]; then bus-1 config reads work. Idempotent. Returns the
/// RP1 endpoint VID/DID read back after enumeration (want 0x00011de4).
///   RC+0x04  command: |= MSE|BME (0x06)
///   RC+0x043c class:  [23:0]=0x060400 (present as PCI bridge)
///   RC+0x18/19/1a:    primary=0 / secondary=1 / subordinate=1  (one u32 write 0x00010100)
///   RC+0x4068 status: verify DL_ACTIVE(0x20)|PHYLINKUP(0x10)
#[cfg(feature = "mipdump")]
pub fn pcie_bridge_enumerate() -> u32 {
    const IDX: usize = PCIE_RC + 0x9000;
    const DATA: usize = PCIE_RC + 0x8000;
    const RP1_ECAM: u32 = 1 << 20; // bus 1, devfn 0
    unsafe {
        let status = read_volatile((PCIE_RC + 0x4068) as *const u32);
        // RC own config (root bus): direct at PCIE_RC + reg.
        let rc = |o: usize| -> u32 { read_volatile((PCIE_RC + o) as *const u32) };
        let rcw = |o: usize, v: u32| { write_volatile((PCIE_RC + o) as *mut u32, v) };
        // Present the RC as a PCI bridge so the class-based logic + bus regs apply.
        let cls = rc(0x43c);
        rcw(0x43c, (cls & 0xff00_0000) | 0x0060_0400);
        // primary=0, secondary=1, subordinate=1, latency=0  -> 0x00_01_01_00 at +0x18.
        rcw(0x18, 0x0001_0100);
        // MSE|BME on the RC.
        let cmd = rc(0x04);
        rcw(0x04, cmd | 0x06);
        core::arch::asm!("dsb sy");
        // Now a bus-1 config read should return the RP1 VID/DID (0x1de4:0x0001).
        write_volatile(IDX as *mut u32, RP1_ECAM);
        core::arch::asm!("dsb sy");
        let vid = read_volatile(DATA as *const u32);
        crate::_print(format_args!(" [DRV1] PCIe enumerate: RC status(0x4068)={:#010x} (DL_ACTIVE|PHYLINKUP want 0x30 bits) class {:#010x}->{:#010x} cmd {:#06x}->{:#06x}\n",
            status, cls, rc(0x43c), cmd, rc(0x04)));
        crate::_print(format_args!(" [DRV1] PCIe enumerate: RP1 bus1 VID/DID now={:#010x} (want 0x00011de4; still 0xffffffff => link not up or bus regs rejected)\n", vid));
        vid
    }
}

/// DRV-1 (the last piece): walk the RP1 endpoint's PCIe config space and PROGRAM its
/// standard PCI MSI-X TABLE entry for the ETH source so an RX-complete raises a real
/// interrupt. Devicetree ground truth (bcm2712.dtsi): `pcie2 msi-parent = <&mip0>`,
/// and `mip0 msi-ranges = <&gicv2 GIC_SPI 128 EDGE_RISING 64>` — so MIP vector v maps
/// to GIC SPI (128+v); vector 6 → SPI 134 → INTID 166 (heqk's existing constant). The
/// doorbell 0xf_ffff_fffc is mip0's PCIe-visible page. rp1.c shows MSIX_CFG is enable-
/// only; the addr/data live in a real PCI MSI-X table in an RP1 BAR.
///
/// Config access (pcie-brcmstb.c, bcm7712 offsets): write PCIE_ECAM_OFFSET(bus,devfn,0)
/// = (bus<<20)|(devfn<<12) to EXT_CFG_INDEX (RC+0x9000); the device's 4 KiB config
/// space is then a window at EXT_CFG_DATA (RC+0x8000)+(reg&0xfff). RP1 = bus 1, dev 0.
///
/// SAFETY: the whole RP1 BAR window (GB 112) and the RC config window (GB 64) are
/// inside the mmu_cm5 identity map (GB 4..511 Device-nGnRnE), so every access here is
/// mapped — no fault risk from any BAR offset. The programmed target 0xf_ffff_fffc is
/// MIP doorbell MMIO, not system RAM, so it cannot scribble memory (DRV-2 moot). Every
/// value is dumped and the table write is read-back-verified. Returns the read-back of
/// the programmed `data` dword (want 6), or 0 if no MSI-X capability was found.
#[cfg(feature = "mipdump")]
pub fn rx_msix_program() -> u32 {
    const IDX: usize = PCIE_RC + 0x9000; // EXT_CFG_INDEX (bcm7712)
    const DATA: usize = PCIE_RC + 0x8000; // EXT_CFG_DATA window base
    const RP1_ECAM: u32 = (1 << 20) | (0 << 12); // bus 1, devfn 0
    const ETH_VEC: usize = 6; // RP1_INT_ETH → MIP vector 6 → SPI 134 / INTID 166
    unsafe {
        write_volatile(IDX as *mut u32, RP1_ECAM);
        core::arch::asm!("dsb sy");
        let cr = |reg: usize| -> u32 { read_volatile((DATA + (reg & 0xfff)) as *const u32) };
        let cw = |reg: usize, v: u32| { write_volatile((DATA + (reg & 0xfff)) as *mut u32, v) };

        let id = cr(0x00);
        // Bus-Master-Enable + Memory-Space-Enable on the RP1 endpoint — without BME the
        // RP1 physically cannot issue the upstream MSI memory write.
        let cmd0 = cr(0x04);
        cw(0x04, cmd0 | 0x06);
        core::arch::asm!("dsb sy");
        let statuscmd = cr(0x04);
        crate::_print(format_args!(" [DRV1] RP1 cfg: VID/DID={:#010x} CMD {:#06x}->{:#06x} (MSE|BME)\n",
            id, cmd0 & 0xffff, statuscmd & 0xffff));

        // Walk the capability list: byte 0x34 → first cap ptr; each cap dword is
        // [id | next<<8 | cap-specific<<16]. MSI-X cap id = 0x11.
        let mut cap = (cr(0x34) & 0xfc) as usize;
        let mut msix = 0usize;
        let mut guard = 0;
        while cap != 0 && cap != 0xfc && guard < 48 {
            let w0 = cr(cap);
            let this_id = w0 & 0xff;
            let next = ((w0 >> 8) & 0xfc) as usize;
            crate::_print(format_args!("   cap@{:#04x} id={:#04x} next={:#04x}\n", cap, this_id, next));
            if this_id == 0x11 { msix = cap; break; }
            cap = next;
            guard += 1;
        }
        if msix == 0 {
            crate::_print(format_args!(" [DRV1] no MSI-X capability on RP1 — cannot program table\n"));
            return 0;
        }
        // MSI-X cap: +0 [id|next|msgctrl<<16], +4 table off/BIR, +8 pba off/BIR.
        let msgctrl = cr(msix) >> 16;
        let toffbir = cr(msix + 4);
        let bir = (toffbir & 0x7) as usize;
        let toff = (toffbir & !0x7) as usize;
        let tsize = (msgctrl & 0x7ff) + 1;
        crate::_print(format_args!(" [DRV1] MSI-X cap@{:#04x}: msgctrl={:#06x} (size={} en={} fmask={}) tbl BIR={} off={:#x}\n",
            msix, msgctrl & 0xffff, tsize, (msgctrl >> 15) & 1, (msgctrl >> 14) & 1, bir, toff));
        // Read BAR[bir] (a PCIe address); RP1's BAR is 64-bit prefetchable.
        let bar_lo = cr(0x10 + bir * 4);
        let bar_hi = cr(0x10 + bir * 4 + 4);
        // BAR type: bits[2:1]=10 => 64-bit (consumes the next BAR as the high dword);
        // otherwise 32-bit (RP1's BARs are all 32-bit non-prefetchable per the datasheet).
        let is64 = (bar_lo & 0x6) == 0x4;
        let bar_full = if is64 {
            (((bar_hi as u64) << 32) | ((bar_lo & !0xf) as u64)) as usize
        } else {
            (bar_lo & !0xf) as usize
        };
        crate::_print(format_args!(" [DRV1] BAR{}={:#010x} (is64={}) BAR{}_hi={:#010x} → PCIe {:#x}\n",
            bir, bar_lo, is64, bir + 1, bar_hi, bar_full));
        // dt ranges: 64-bit prefetch PCIe 0x4_0000_0000 → CPU 0x1c_0000_0000;
        //            32-bit          PCIe 0x0         → CPU 0x1f_0000_0000.
        let cpu_bar = if bar_full >= 0x4_0000_0000 {
            bar_full - 0x4_0000_0000 + 0x1c_0000_0000
        } else {
            bar_full + 0x1f_0000_0000
        };
        let table_cpu = cpu_bar + toff;
        let ent = table_cpu + ETH_VEC * 16;
        crate::_print(format_args!(" [DRV1] table CPU={:#x} (bar→cpu {:#x} + off {:#x}); entry[{}] @ {:#x}\n",
            table_cpu, cpu_bar, toff, ETH_VEC, ent));
        // Guard: the table must land inside the identity-mapped device window (GB 4..511).
        if !(0x1_0000_0000..0x80_0000_0000).contains(&ent) {
            crate::_print(format_args!(" [DRV1] entry addr outside identity map — refusing to write\n"));
            return 0;
        }
        let er = |o: usize| -> u32 { read_volatile((ent + o) as *const u32) };
        crate::_print(format_args!(" [DRV1] MSI-X[{}] BEFORE: addr={:#010x}_{:08x} data={:#010x} vctrl={:#010x}\n",
            ETH_VEC, er(0x4), er(0x0), er(0x8), er(0xc)));
        // Program: mip0 doorbell 0xff_ffff_f000 (PCIe addr; dma-ranges -> CPU 0x10_0013_0000
        // = MIP_INT_RAISE), data = MIP vector 6 (mip_compose_msi_msg: msg.data = hwirq),
        // unmask (vctrl bit0=0). NOT the RC doorbell 0xf_ffff_fffc — that block is unused on
        // BCM2712 (pcie2 msi-parent = mip0).
        write_volatile((ent + 0x0) as *mut u32, 0xffff_f000); // addr_lo
        write_volatile((ent + 0x4) as *mut u32, 0x0000_00ff); // addr_hi -> 0xff_ffff_f000
        write_volatile((ent + 0x8) as *mut u32, ETH_VEC as u32); // data = vector 6
        write_volatile((ent + 0xc) as *mut u32, 0x0000_0000); // unmask
        core::arch::asm!("dsb sy");
        crate::_print(format_args!(" [DRV1] MSI-X[{}] AFTER:  addr={:#010x}_{:08x} data={:#010x} vctrl={:#010x}\n",
            ETH_VEC, er(0x4), er(0x0), er(0x8), er(0xc)));
        // Enable MSI-X globally + clear the function mask (msgctrl bit15=1, bit14=0).
        write_volatile(IDX as *mut u32, RP1_ECAM);
        core::arch::asm!("dsb sy");
        let mc_pre = cr(msix);
        let mc_new = (mc_pre & !(1u32 << (16 + 14))) | (1u32 << (16 + 15));
        cw(msix, mc_new);
        core::arch::asm!("dsb sy");
        let mc_post = cr(msix);
        crate::_print(format_args!(" [DRV1] MSI-X enable: msgctrl {:#010x} → {:#010x} (want b31 set, b30 clear)\n",
            mc_pre, mc_post));
        er(0x8)
    }
}

/// DRV-1 DECISIVE EXPERIMENT (mipdump): the RP1 endpoint's MSI-X table is unreadable
/// (config-space access via EXT_CFG returns 0xffffffff on metal), so we cannot see
/// which doorbell the ETH source targets. Both candidate MSI sinks are fully known
/// from the RPi Linux source, so unmask BOTH and let the hardware tell us which one
/// latches when RX frames flow — no guessing:
///   * mip0 (dt-canonical, irq-bcm2712-mip.c): base 0x10_0013_0000, doorbell PCIe
///     0xff_fffff000, data=vector, GIC SPI (v+128) edge. Unmask HOST = write 0 to
///     MASKL/H_HOST (0x40/0x50), ~0 to CFGL/H_HOST (0x20/0x30 = route to HOST).
///   * RC MSI (firmware-programmed, pcie-brcmstb.c): base 0x10_0012_0000+0x4500,
///     doorbell 0xf_ffff_fffc, data=0x6540|v, GIC SPI 234 level. Unmask = MASK_CLR
///     (0x4514); clear stale = CLR (0x4508).
/// Both register windows are inside the mmu_cm5 GB4..511 identity map (mapped, safe).
/// Read-mostly: no GIC routing here — this only reveals the sink+vector so the real
/// wiring afterwards is correct, not guessed.
#[cfg(feature = "mipdump")]
pub fn msi_sink_unmask() {
    const MIP: usize = 0x10_0013_0000; // mip0 reg[0] (CPU)
    const RC: usize = PCIE_RC + 0x4500; // brcmstb RC MSI INTR2 base
    unsafe {
        // mip0: route to HOST + unmask all 64 HOST vectors, and MASK the VPU copy so the
        // interrupt is delivered to the host GIC (irq-bcm2712-mip.c:189-194 init sequence).
        write_volatile((MIP + 0x20) as *mut u32, 0xffff_ffff); // CFGL_HOST
        write_volatile((MIP + 0x30) as *mut u32, 0xffff_ffff); // CFGH_HOST
        write_volatile((MIP + 0x40) as *mut u32, 0x0000_0000); // MASKL_HOST (0=unmasked)
        write_volatile((MIP + 0x50) as *mut u32, 0x0000_0000); // MASKH_HOST
        write_volatile((MIP + 0x60) as *mut u32, 0xffff_ffff); // MASKL_VPU (mask VPU)
        write_volatile((MIP + 0x70) as *mut u32, 0xffff_ffff); // MASKH_VPU
        // RC MSI: clear stale, then unmask all 32.
        write_volatile((RC + 0x8) as *mut u32, 0xffff_ffff); // MSI_INT_CLR
        write_volatile((RC + 0x14) as *mut u32, 0xffff_ffff); // MSI_INT_MASK_CLR
        core::arch::asm!("dsb sy");
    }
}

/// DRV-1 experiment readout (mipdump): the two candidate sinks' pending-status
/// registers. Returns (mip_statusL, mip_statusH, rc_status). A nonzero value while
/// RX frames flow reveals which doorbell the RP1 ETH source actually targets and the
/// vector bit — the fact the metal MSI-X-table read could not give us.
#[cfg(feature = "mipdump")]
pub fn msi_sink_status() -> (u32, u32, u32) {
    const MIP: usize = 0x10_0013_0000;
    const RC: usize = PCIE_RC + 0x4500;
    unsafe {
        (
            read_volatile((MIP + 0x80) as *const u32), // STATUSL_HOST
            read_volatile((MIP + 0x90) as *const u32), // STATUSH_HOST
            read_volatile((RC + 0x0) as *const u32),   // MSI_INT_STATUS
        )
    }
}

/// DRV-1 DECISIVE SPLIT (mipdump): the RP1 PCIE_CFG block's RAW per-source interrupt
/// status (RP1 peripherals datasheet Table 90/91: INTSTATL 0x108 = sources [31:0],
/// INTSTATH 0x10c = [63:32]). PCIE_CFG base = RP1 0x108000 -> CPU 0x1C_0010_8000.
/// This is BEFORE the MSIX_CFG mask/generation, so it tells us whether the GEM (source
/// RP1_INT_ETH=6, i.e. INTSTATL bit 6) actually ASSERTS into the RP1 interrupt block at
/// all. Read under sustained RX it splits the two remaining hypotheses cleanly:
///   * bit6 SETS but no sink latches  => GEM->RP1 works; the ONLY gap is the unprogrammed
///     PCI MSI-X table (addr/data) — focus there (RC downstream cfg vs RP1 DBI).
///   * bit6 STAYS 0                    => the GEM never reaches the RP1 vector block — a
///     GEM/RP1-internal routing/enable gap, NOT the table.
/// Returns (INTSTATL, INTSTATH).
#[cfg(feature = "mipdump")]
pub fn rp1_intstat() -> (u32, u32) {
    const PCIE_CFG: usize = 0x1C_0010_8000;
    unsafe {
        (
            read_volatile((PCIE_CFG + 0x108) as *const u32),
            read_volatile((PCIE_CFG + 0x10c) as *const u32),
        )
    }
}

/// P8 (RP1 RX-IRQ) — unmask the GEM **receive-complete** interrupt so an RX frame
/// raises RP1 internal source 6 → MSI-X → mip0 → GIC SPI 134 / INTID 166 (instead
/// of pure polling). Pairs with `Gic::enable_spi(166)` + a `handle_irq` branch.
pub fn rx_irq_enable() {
    w(GEM, IER, INT_RCOMP);
}

/// Acknowledge a GEM RX interrupt: read ISR (read-to-clear) and clear the RSR
/// receive flag. Returns the ISR value. Call from the INTID-166 IRQ branch.
pub fn rx_irq_ack() -> u32 {
    let isr = r(GEM, ISR);
    w(GEM, RSR, RSR_REC); // W1C the received flag
    isr
}

/// Physical base of the RX descriptor ring (== RXRING, page-aligned). An EL0 RX
/// driver server is granted a Normal-NC window onto this page to poll descriptors
/// coherently (no cache ops, which EL0 can't do). P7c step 3b stage 2.
pub fn rxring_pa() -> usize {
    unsafe { core::ptr::addr_of!(RXRING.desc) as usize }
}
/// Number of RX descriptors and the descriptor stride (bytes), for an EL0 driver
/// that walks the ring.
pub const RX_NDESC: usize = NRX;
pub const RX_DESC_STRIDE: usize = DESC_SZ;

/// P7c step 3b stage 4 — read the frame in RX buffer `i` into `out` (invalidate
/// first; the buffer is cacheable). No recycle — the EL0 driver located the frame
/// at descriptor `i`; the kernel packet-engine reads it here to run the verdict.
pub fn peek_rx_frame(i: usize, out: &mut [u8]) -> usize {
    let i = i % NRX;
    let bufpa = unsafe { core::ptr::addr_of!(RXRING.buf[i]) as usize };
    let n = out.len().min(RXBUF);
    dc_ivac(bufpa, n);
    for k in 0..n {
        out[k] = unsafe { read_volatile((bufpa + k) as *const u8) };
    }
    n
}

/// AUDIT M-7 — hardware-reported frame length for RX descriptor `i`, read from the
/// GEM's OWN status writeback through the NC alias.
///
/// The kernel must NOT take the IDS input length from an EL0 driver's report: that
/// driver is precisely the component the P7c threat model assumes may be
/// compromised, and a hostile one can report a length that truncates a frame before
/// the offset a rule inspects, or point at a descriptor whose buffer still holds a
/// previous, benign frame — making the packet engine classify something other than
/// what arrived on the wire. That is IDS evasion by the isolated driver.
///
/// Returns None if the descriptor is not actually SW-owned (nothing was received)
/// or the length is implausible, so the caller fails closed.
pub fn rx_desc_status(i: usize) -> Option<usize> {
    let i = i % NRX;
    let dphys = unsafe { core::ptr::addr_of!(RXRING.desc[i]) as usize };
    let d = nc_desc(dphys);
    let w0 = unsafe { read_volatile(d.add(0)) };
    if w0 & RXD_USED == 0 {
        return None; // GEM still owns it — no frame here
    }
    let ctrl = unsafe { read_volatile(d.add(1)) };
    let len = (ctrl & RXD_FRMLEN) as usize;
    if (14..=RXBUF).contains(&len) {
        Some(len)
    } else {
        None
    }
}

/// Is RX descriptor `i` owned by SOFTWARE (USED set) — i.e. the GEM has delivered a
/// frame into it? Distinct from `rx_desc_status`, which also validates the length and
/// returns `None` for BOTH "not delivered" and "delivered but bad length". The batch
/// drainer needs to tell those apart: a delivered-but-bad descriptor must still be
/// CONSUMED and RECYCLED (and its cursor advanced), exactly as Linux macb advances
/// `rx_tail` on any RX_USED descriptor regardless of the frame's validity — otherwise a
/// single malformed frame stalls the whole ring at that slot.
#[inline]
pub fn rx_desc_used(i: usize) -> bool {
    let i = i % NRX;
    let dphys = unsafe { core::ptr::addr_of!(RXRING.desc[i]) as usize };
    let d = nc_desc(dphys);
    (unsafe { read_volatile(d.add(0)) } & RXD_USED) != 0
}

/// Re-arm RX descriptor `i` (clear USED, preserve WRAP) so the GEM refills it —
/// the kernel calls this after the EL0 driver's delivered frame is consumed, so
/// the continuous driver server sees fresh frames. P7c step 4d.
pub fn recycle_rx(i: usize) {
    let i = i % NRX;
    let dphys = unsafe { core::ptr::addr_of!(RXRING.desc[i]) as usize };
    let bufpa = unsafe { core::ptr::addr_of!(RXRING.buf[i]) as u64 };
    let d = nc_desc(dphys);
    let mut nw0 = ((bufpa + DMA_BUS_OFFSET) as u32) & !0x3;
    if i == NRX - 1 {
        nw0 |= RXD_WRAP;
    }
    unsafe {
        // ORDER IS PART OF THE CONTRACT — from the reference driver for this controller,
        // Linux drivers/net/ethernet/cadence/macb_main.c:1451-1456:
        //
        //     desc->ctrl = 0;
        //     /* Setting addr clears RX_USED and allows reception,
        //      * make sure ctrl is cleared first to avoid a race.
        //      */
        //     dma_wmb();
        //     macb_set_addr(bp, desc, paddr);
        //
        // Writing word0 is what CLEARS RX_USED and hands the descriptor back to the
        // controller — i.e. it is the ownership release, and everything the controller
        // may read must already be settled before it. This path previously wrote word0
        // ALONE, leaving word1 holding the PREVIOUS frame's status/length while the
        // descriptor was live again, with no barrier between the two. Clear word1 first,
        // publish it, then release ownership.
        write_volatile(d.add(1), 0); // ctrl/status — clear BEFORE releasing ownership
        core::arch::asm!("dsb sy"); // == dma_wmb(): word1 visible before word0 lands
        write_volatile(d.add(0), nw0); // clears RX_USED -> controller owns it again
        core::arch::asm!("dsb sy");
    }
}

/// Physical base of the TX descriptor ring (== TXRING). P7c step 3b stage 3.
pub fn txring_pa() -> usize {
    unsafe { core::ptr::addr_of!(TXRING.desc) as usize }
}
/// Byte offset of the TX data buffer within the TX ring window (desc + buf).
pub fn tx_buf_offset() -> usize {
    unsafe {
        core::ptr::addr_of!(TXRING.buf) as usize - core::ptr::addr_of!(TXRING.desc) as usize
    }
}

/// P7c step 3b stage 3 — prepare a TX for an EL0 driver to launch: fill the TX
/// buffer with a `len`-byte broadcast marker frame (cleaned to DRAM for the GEM),
/// and set the descriptor's address words, leaving word1 IDLE so the EL0 driver
/// arms + kicks it. The kernel does the privileged buffer/address setup; the EL0
/// driver does the descriptor-arm + TSTART kick + completion poll.
pub fn tx_prep_el0(len: usize) {
    let n = len.min(TXBUF);
    let bufpa = unsafe {
        let tr = &mut *core::ptr::addr_of_mut!(TXRING);
        for k in 0..n {
            tr.buf[0][k] = 0xaa; // marker payload
        }
        for k in 0..6 {
            tr.buf[0][k] = 0xff; // broadcast dst MAC (a benign, real-shaped frame)
        }
        tr.buf[0].as_ptr() as usize
    };
    dc_cvac(bufpa, n); // TX buffer is cacheable — publish it to DRAM for the GEM
    let bus = bufpa as u64 + DMA_BUS_OFFSET;
    let dphys = unsafe { core::ptr::addr_of!(TXRING.desc[0]) as usize };
    let d = nc_desc(dphys); // NC alias — coherent with the EL0 driver's NC window
    unsafe {
        write_volatile(d.add(0), bus as u32); // word0 addr_lo (USED=0)
        // word1 IDLE (EL0 arms it). NO WRAP: with NTX>=2, desc[0] is not the last slot —
        // WRAP belongs on desc[NTX-1] and putting it here would truncate the ring to one
        // entry, reintroducing the prefetch-aliasing defect this ring depth exists to fix.
        write_volatile(d.add(1), TXD_USED);
        write_volatile(d.add(2), (bus >> 32) as u32); // word2 addr_hi
        write_volatile(d.add(3), 0);
        write_volatile(d.add(4), 0);
        write_volatile(d.add(5), 0);
        core::arch::asm!("dsb sy");
    }
}
