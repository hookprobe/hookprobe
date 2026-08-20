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

const NRX: usize = 8;
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

const NTX: usize = 1; // single-descriptor synchronous TX (send-one, poll-complete)
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
    let bus = unsafe { core::ptr::addr_of!(TXRING.buf[0]) as u64 } + DMA_BUS_OFFSET;
    let d = nc_desc(dphys);
    unsafe {
        write_volatile(d.add(0), bus as u32);
        write_volatile(d.add(1), TXD_USED | TXD_WRAP); // USED=1 (idle) + WRAP (only descriptor)
        write_volatile(d.add(2), (bus >> 32) as u32); // addr high (= 0x10)
        write_volatile(d.add(3), 0); // resvd
        write_volatile(d.add(4), 0); // ts_1 (PTP)
        write_volatile(d.add(5), 0); // ts_2 (PTP)
        core::arch::asm!("dsb sy");
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
    let bufpa = unsafe {
        let tr = &mut *core::ptr::addr_of_mut!(TXRING);
        for k in 0..n {
            tr.buf[0][k] = bytes[k];
        }
        tr.buf[0].as_ptr() as usize
    };
    dc_cvac(bufpa, n); // TX buffer is cacheable — clean so the device reads the frame
    let dphys = unsafe { core::ptr::addr_of!(TXRING.desc[0]) as usize };
    let d = nc_desc(dphys); // NC alias — coherent, no descriptor cache maintenance
    let bus = bufpa as u64 + DMA_BUS_OFFSET;
    unsafe {
        write_volatile(d.add(0), bus as u32); // word0 addr_lo
        write_volatile(d.add(2), (bus >> 32) as u32); // word2 addr_hi
        // word1: length | LAST | WRAP, USED=0 — hand the descriptor to HW. The GEM
        // auto-pads to the 60B minimum and appends the FCS (NOCRC not set).
        write_volatile(d.add(1), (n as u32 & RXD_FRMLEN) | TXD_LAST | TXD_WRAP);
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
    w(GEM, NCR, NCR_RE | NCR_TE | NCR_MPE | NCR_TSTART); // kick the TX DMA
    // Poll for completion: HW sets USED (bit31) in word1 when the frame is out.
    let mut spins = 0u32;
    loop {
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
        if spins >= 500_000 {
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

/// Current Receive Status register (for diagnostics: BNA/REC/overrun).
pub fn rsr() -> u32 {
    r(GEM, RSR)
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
        write_volatile(d.add(0), nw0);
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
        write_volatile(d.add(1), TXD_USED | TXD_WRAP); // word1 IDLE (EL0 arms it)
        write_volatile(d.add(2), (bus >> 32) as u32); // word2 addr_hi
        write_volatile(d.add(3), 0);
        write_volatile(d.add(4), 0);
        write_volatile(d.add(5), 0);
        core::arch::asm!("dsb sy");
    }
}
