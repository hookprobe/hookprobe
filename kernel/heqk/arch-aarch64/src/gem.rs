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
const RP1_IO_BANK1: usize = 0x1C00_d4000;
const RP1_RIO1: usize = 0x1C00_e4000;
const RP1_PADS1: usize = 0x1C00_f4000;
const ETH_RST_IDX: usize = 4; // GPIO32 within bank1
const RIO_SET: usize = 0x2000; // atomic set-bits alias
const RIO_CLR: usize = 0x3000; // atomic clear-bits alias

// --- GEM register offsets (Cadence MACB / GEM) --------------------------------
const NCR: usize = 0x000; // Network Control
const NCFGR: usize = 0x004; // Network Config
const NSR: usize = 0x008; // Network Status
const DMACFG: usize = 0x010; // DMA Config (GEM)
const RBQP: usize = 0x018; // RX buffer queue base (low)
const RSR: usize = 0x020; // Receive Status
const IDR: usize = 0x02c; // Interrupt Disable (mask all)
const RBQPH: usize = 0x4d4; // RX buffer queue base (high, 64-bit)

// NCR bits
const NCR_RE: u32 = 1 << 2; // receive enable
const NCR_TE: u32 = 1 << 3; // transmit enable
const NCR_MPE: u32 = 1 << 4; // MDIO enable
// NCFGR bits
const NCFGR_CAF: u32 = 1 << 4; // copy-all-frames (promiscuous)
const NCFGR_MDC_DIV128: u32 = 6 << 18; // GEM_CLK: pclk/128 (~1.5 MHz MDC @200 MHz)
// DMACFG bits
const DMACFG_ADDR64: u32 = 1 << 30;
// RX descriptor word0 flags (in the low bits of the buffer address)
const RXD_USED: u32 = 1 << 0; // 0 = HW-owned; HW sets 1 after writing a frame
const RXD_WRAP: u32 = 1 << 1; // last descriptor
// RX descriptor word1 (ctrl/status) fields
const RXD_FRMLEN: u32 = 0x3fff; // GEM: 14-bit frame length
// RSR bits
const RSR_BNA: u32 = 1 << 0; // buffer not available (DMA target unreachable)
const RSR_REC: u32 = 1 << 1; // frame received

/// The DMA bus-address offset: GEM bus address = CPU physical + this.
const DMA_BUS_OFFSET: u64 = 0x10_0000_0000;

const NRX: usize = 8;
const RXBUF: usize = 2048;

/// RX ring + buffers, page-aligned, in kernel RAM (identity-mapped: VA == PA).
#[repr(C, align(4096))]
struct RxRing {
    desc: [[u32; 4]; NRX], // 16-byte DMA64 descriptors
    buf: [[u8; RXBUF]; NRX],
}
static mut RXRING: RxRing = RxRing {
    desc: [[0; 4]; NRX],
    buf: [[0; RXBUF]; NRX],
};

#[inline]
fn r(base: usize, off: usize) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}
#[inline]
fn w(base: usize, off: usize, v: u32) {
    unsafe { write_volatile((base + off) as *mut u32, v) };
}
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
        write_volatile((RP1_IO_BANK1 + 8 * ETH_RST_IDX + 4) as *mut u32, 5);
        // Output-enable the pin (RIO OE at offset 0x04, atomic SET).
        write_volatile((RP1_RIO1 + RIO_SET + 0x04) as *mut u32, bit);
        // Drive LOW = assert reset (active-low): RIO OUT (0x00) atomic CLR.
        write_volatile((RP1_RIO1 + RIO_CLR + 0x00) as *mut u32, bit);
        for _ in 0..3_000_000u32 {
            core::hint::spin_loop();
        } // ≥5 ms
        // Drive HIGH = release reset: RIO OUT atomic SET.
        write_volatile((RP1_RIO1 + RIO_SET + 0x00) as *mut u32, bit);
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

/// Bring up polled RX. Returns the ring base (cpu phys) for diagnostics.
pub fn rx_init() -> usize {
    enable_clocks();
    phy_reset();

    let ring = core::ptr::addr_of_mut!(RXRING) as usize;
    // Build the RX ring: each descriptor points at its buffer (bus addr =
    // cpu_phys + 0x10_0000_0000), HW-owned (USED=0); last has WRAP.
    unsafe {
        let rr = &mut *core::ptr::addr_of_mut!(RXRING);
        for i in 0..NRX {
            let bufpa = rr.buf[i].as_ptr() as u64; // cpu phys (identity)
            let bus = bufpa + DMA_BUS_OFFSET;
            let mut w0 = (bus as u32) & !0x3; // low addr; USED=0 (hw-owned)
            if i == NRX - 1 {
                w0 |= RXD_WRAP;
            }
            rr.desc[i][0] = w0;
            rr.desc[i][1] = 0;
            rr.desc[i][2] = (bus >> 32) as u32; // addr high (= 0x10)
            rr.desc[i][3] = 0;
        }
    }
    // Publish descriptors to DRAM (non-coherent DMA reads them).
    dc_civac(ring, core::mem::size_of::<RxRing>());

    // Quiesce, mask IRQs (polled), configure DMA64 + RX buffer size, ring base.
    w(GEM, NCR, 0);
    w(GEM, IDR, 0xffff_ffff);
    let _ = r(GEM, RSR);
    w(GEM, RSR, RSR_BNA | RSR_REC); // clear sticky status
    let rxbs = (RXBUF / 64) as u32; // RX buffer size in 64-byte units
    w(GEM, DMACFG, DMACFG_ADDR64 | (rxbs << 16) | 0x10 /*burst*/);
    let ringbus = ring as u64 + DMA_BUS_OFFSET;
    w(GEM, RBQPH, (ringbus >> 32) as u32); // high FIRST
    w(GEM, RBQP, ringbus as u32);
    // Promiscuous + accept broadcast (NBC=0), MDC divider, then enable RX.
    w(GEM, NCFGR, NCFGR_CAF | NCFGR_MDC_DIV128);
    w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE);
    ring
}

/// Poll the RX ring once. If a frame is ready, copy up to `out.len()` bytes into
/// `out` and recycle the descriptor; returns Some(frame_len). None = nothing yet.
pub fn poll_rx(out: &mut [u8]) -> Option<usize> {
    // Rotating consumer index across calls.
    static mut IDX: usize = 0;
    let i = unsafe { IDX % NRX };
    let dptr = unsafe { core::ptr::addr_of_mut!(RXRING.desc[i]) as usize };
    // Invalidate the descriptor line so we see HW's write to the USED bit.
    dc_civac(dptr, 16);
    let w0 = unsafe { read_volatile(dptr as *const u32) };
    if w0 & RXD_USED == 0 {
        return None; // still HW-owned: no frame yet
    }
    let ctrl = unsafe { read_volatile((dptr + 4) as *const u32) };
    let len = (ctrl & RXD_FRMLEN) as usize;
    let bufpa = unsafe { core::ptr::addr_of!(RXRING.buf[i]) as usize };
    dc_civac(bufpa, len.min(RXBUF)); // invalidate before reading DMA'd data
    let n = len.min(out.len()).min(RXBUF);
    for k in 0..n {
        out[k] = unsafe { read_volatile((bufpa + k) as *const u8) };
    }
    // Recycle: re-arm the descriptor (USED=0), preserve WRAP, republish.
    unsafe {
        let bus = bufpa as u64 + DMA_BUS_OFFSET;
        let mut nw0 = (bus as u32) & !0x3;
        if i == NRX - 1 {
            nw0 |= RXD_WRAP;
        }
        write_volatile((dptr + 4) as *mut u32, 0);
        write_volatile(dptr as *mut u32, nw0);
        IDX = IDX.wrapping_add(1);
    }
    dc_civac(dptr, 16);
    Some(len)
}

/// Current Receive Status register (for diagnostics: BNA/REC/overrun).
pub fn rsr() -> u32 {
    r(GEM, RSR)
}
