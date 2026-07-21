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
const RBQP: usize = 0x018; // RX buffer queue base (low)
const RSR: usize = 0x020; // Receive Status
const IDR: usize = 0x02c; // Interrupt Disable (mask all)
const RBQPH: usize = 0x4d4; // RX buffer queue base (high, 64-bit)

// NCR bits
const NCR_RE: u32 = 1 << 2; // receive enable
const NCR_TE: u32 = 1 << 3; // transmit enable
const NCR_MPE: u32 = 1 << 4; // MDIO enable
// NCFGR bits
const NCFGR_FD: u32 = 1 << 1; // full duplex
const NCFGR_CAF: u32 = 1 << 4; // copy-all-frames (promiscuous)
const NCFGR_GBE: u32 = 1 << 10; // gigabit mode (DDR RX sampling) — REQUIRED for 1G RX
const NCFGR_MDC_DIV128: u32 = 6 << 18; // GEM_CLK: pclk/128 (~1.5 MHz MDC @200 MHz)
// DMACFG bits
const DMACFG_ADDR64: u32 = 1 << 30;
// RP1's GEM_GXL is FULL store-and-forward ONLY (partial SF not implemented), which
// requires the packet-buffer memory-size fields to select the full addressable
// space — else HW receives the frame + sets USED but writes a ZERO ctrl/status
// word (no length). Both Linux macb_configure_dma() and U-Boot set these
// unconditionally. Omitting them is the RP1 GEM descriptor-length ("w1=0") bug.
const DMACFG_RXBMS: u32 = 3 << 8; // RX packet buffer: full configured size
const DMACFG_TXPBMS: u32 = 1 << 10; // TX packet buffer: full size
// NOTE: RX/TX Buffer-Descriptor EXTENDED mode (DMACFG bit28/bit29) was tried on
// metal as a candidate cure for the "w1=0" quirk (theory: it gates the word1
// status writeback under ADDR64). It did NOT populate word1 even on a correctly-
// aligned descriptor, AND it WIDENS the descriptor with PTP timestamp words —
// which corrupts this 16-byte-stride ring (a stray word0=0x00000001 appeared and
// frames dropped 3→2). So it is deliberately NOT set. See RP1_GEM_BRINGUP.md.
// RX descriptor word0 flags (in the low bits of the buffer address)
const RXD_USED: u32 = 1 << 0; // 0 = HW-owned; HW sets 1 after writing a frame
const RXD_WRAP: u32 = 1 << 1; // last descriptor
// RX descriptor word1 (ctrl/status) fields
const RXD_FRMLEN: u32 = 0x3fff; // GEM: 14-bit frame length (RP1 sets JUMBO caps)
// RSR bits
const RSR_BNA: u32 = 1 << 0; // buffer not available (DMA target unreachable)
const RSR_REC: u32 = 1 << 1; // frame received

/// The DMA bus-address offset: GEM bus address = CPU physical + this.
const DMA_BUS_OFFSET: u64 = 0x10_0000_0000;

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
    dc_cvac(ring, core::mem::size_of::<RxRing>()); // clean: device reads these

    // Quiesce, mask IRQs (polled), configure DMA64 + RX buffer size, ring base.
    w(GEM, NCR, 0);
    w(GEM, IDR, 0xffff_ffff);
    let _ = r(GEM, RSR);
    w(GEM, RSR, RSR_BNA | RSR_REC); // clear sticky status
    let rxbs = (RXBUF / 64) as u32; // RX buffer size in 64-byte units
    // ADDR64 + full-SF buffer sizing (RXBMS|TXPBMS) + INCR16 burst => 0x40200710.
    w(GEM, DMACFG, DMACFG_ADDR64 | DMACFG_RXBMS | DMACFG_TXPBMS | (rxbs << 16) | 0x10);
    let ringbus = ring as u64 + DMA_BUS_OFFSET;
    w(GEM, RBQPH, (ringbus >> 32) as u32); // high FIRST
    w(GEM, RBQP, ringbus as u32);
    // MAC: promiscuous + broadcast, MDC divider, full-duplex, and GIGABIT mode
    // if the link negotiated 1G (required — 1000BASE-T RX is DDR-sampled).
    let mut ncfgr = NCFGR_CAF | NCFGR_MDC_DIV128 | NCFGR_FD;
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
    let dptr = unsafe { core::ptr::addr_of_mut!(RXRING.desc[i]) as usize };
    // Invalidate the descriptor line so we see HW's write to the USED bit.
    dc_ivac(dptr, 16);
    let w0 = unsafe { read_volatile(dptr as *const u32) };
    if w0 & RXD_USED == 0 {
        return None; // still HW-owned: no frame yet
    }
    // The GEM writes the status word (ctrl/w1) BEFORE setting USED (w0), so once
    // USED is seen the length/SOF/EOF is already committed. A short bounded
    // re-read covers any residual PCIe/UBUS write-visibility skew; with the
    // DMACFG full-store-and-forward fix (RXBMS|TXPBMS), ctrl is populated on the
    // first read in practice (previously it stayed 0 — the RP1 GEM bug).
    let mut ctrl = unsafe { read_volatile((dptr + 4) as *const u32) };
    let mut spins = 0u32;
    while ctrl == 0 && spins < 1024 {
        dc_ivac(dptr, 16);
        ctrl = unsafe { read_volatile((dptr + 4) as *const u32) };
        spins += 1;
    }
    let w2 = unsafe { read_volatile((dptr + 8) as *const u32) };
    let w3 = unsafe { read_volatile((dptr + 12) as *const u32) };
    let desc_len = (ctrl & RXD_FRMLEN) as usize;
    let bufpa = unsafe { core::ptr::addr_of!(RXRING.buf[i]) as usize };
    // Copy exactly the received frame (bounded by `out` and the buffer). Fall
    // back to the whole buffer only if the length is still unreported (ctrl==0),
    // in which case the parser self-bounds via the IP header's own total_len.
    let copy_n = if desc_len > 0 {
        desc_len.min(out.len()).min(RXBUF)
    } else {
        out.len().min(RXBUF)
    };
    dc_ivac(bufpa, copy_n); // invalidate the bytes we're about to read from DRAM
    for k in 0..copy_n {
        out[k] = unsafe { read_volatile((bufpa + k) as *const u8) };
    }
    let len = copy_n;
    // Recycle: hand the descriptor back to the GEM by clearing USED in word0
    // ONLY — never rewrite the status word (word1). The GEM overwrites word1 on
    // the next RX; writing 0 here is the documented Cadence macb RX clobber
    // (Linux "net: macb: fix dropped RX frames due to a race"). Because four
    // 16-byte descriptors share one 64-byte cache line, a plain clean of this
    // descriptor writes back the STALE cached copies of its neighbours,
    // squashing a neighbour's just-written status in DRAM (audit finding B-4).
    // So invalidate the line FIRST: the write-allocate then reloads FRESH
    // neighbours, and the clean publishes those (not stale zeros). This is the
    // in-place cacheable-descriptor discipline; a non-cacheable ring (K1) would
    // make the dance unnecessary but is not required to be correct.
    unsafe {
        let bus = bufpa as u64 + DMA_BUS_OFFSET;
        let mut nw0 = (bus as u32) & !0x3; // USED=0 (hw-owned)
        if i == NRX - 1 {
            nw0 |= RXD_WRAP;
        }
        dc_ivac(dptr, 16); // drop the stale line so the clean won't write stale neighbours
        write_volatile(dptr as *mut u32, nw0); // clear USED; leave word1 for the GEM
        dc_cvac(dptr, 16); // publish word0 + freshly-reloaded neighbours
        IDX = IDX.wrapping_add(1);
    }
    Some((len, w0, ctrl, w2, w3))
}

/// Current Receive Status register (for diagnostics: BNA/REC/overrun).
pub fn rsr() -> u32 {
    r(GEM, RSR)
}
