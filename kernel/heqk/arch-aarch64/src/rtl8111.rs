//! P9 — RTL8111H second Ethernet (`eth1`) on BCM2712 external PCIe **RC1**.
//!
//! PREPARED (not yet wired/flashed). Mirrors the proven `gem.rs` patterns: the
//! DMA bus offset (`+0x10_0000_0000`), the GB257 Normal-NC descriptor alias, and
//! the polled-OWN model all carry over unchanged. RC1 (`pcie1 @ 0x10_0011_0000`)
//! is register-identical to RC2 (the RP1's controller `gem.rs` drives) — the only
//! genuinely new work is PCIe link-training (Track A: firmware trains it via
//! `dtparam=pciex1`) + enumeration/BAR assignment. See `P9_P10_BRINGUP.md`.
//!
//! Wire-in order (one console proof-point per stage): rc1_status → cfg vendor-ID
//! → inbound window + BAR2 + MAC → RX first light → TX.

use core::ptr::{read_volatile, write_volatile};

/// GEM bus address = CPU physical + this (identical for RC1/RC2).
const DMA_BUS_OFFSET: u64 = 0x10_0000_0000;
/// Normal-NC alias (mmu_cm5 GB257 → physical GB0): descriptors accessed here only.
const NC_VA: usize = crate::mmu_cm5::NC_ALIAS_VA;
#[inline]
fn nc_desc(phys: usize) -> *mut u32 {
    (phys + NC_VA) as *mut u32
}

// --- BCM2712 external PCIe RC1 (pcie1) controller -----------------------------
const RC1: usize = 0x10_0011_0000; // GB64, Device-mapped (GEM's RC2 = 0x10_0012_0000)
const CFG_INDEX: usize = 0x9000; // write (bus<<20)|(devfn<<12)
const CFG_DATA: usize = 0x8000; // then read/write at +(reg & 0xfff)
const PCIE_STATUS: usize = 0x4068; // DL_ACTIVE=0x20 | PHYLINKUP=0x10
const LINK_UP_MASK: u32 = 0x30;
/// RTL BAR2 (MMIO) is assigned PCIe bus 0x0 → visible at this CPU address
/// (32-bit outbound window, already Device-mapped as GB108).
const RTL_MMIO: usize = 0x1b_0000_0000;

#[inline]
fn rc_r(off: usize) -> u32 {
    unsafe { read_volatile((RC1 + off) as *const u32) }
}
#[inline]
fn rc_w(off: usize, v: u32) {
    unsafe { write_volatile((RC1 + off) as *mut u32, v) };
}

/// GEM's RC2 (the internal x4 link to RP1) — ALWAYS firmware-trained + PLL-locked.
/// Used only as the working REFERENCE to diff against RC1's stuck PLL.
const RC2: usize = 0x10_0012_0000;

#[inline]
fn rc_r_at(base: usize, off: usize) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}
#[inline]
fn rc_w_at(base: usize, off: usize, v: u32) {
    unsafe { write_volatile((base + off) as *mut u32, v) };
}

/// Base-parameterized SERDES MDIO read (port 0, CMD_READ in bits 20+).
fn mdio_read_at(base: usize, regad: u32) -> Option<u16> {
    rc_w_at(base, 0x1100, regad | 0x0010_0000);
    let _ = rc_r_at(base, 0x1100);
    let mut spin = 0u32;
    loop {
        let v = rc_r_at(base, 0x1108);
        if v & 0x8000_0000 != 0 {
            return Some((v & 0xffff) as u16);
        }
        spin += 1;
        if spin >= 200_000 {
            return None;
        }
    }
}
/// Base-parameterized SERDES PLL/SSC status via MDIO. Returns (pll_lock, ssc).
fn serdes_pll_at(base: usize) -> (bool, bool) {
    // SET_ADDR_OFFSET(0x1f) = SSC_REGS_ADDR(0x1100), then read SSC_STATUS(0x1).
    rc_w_at(base, 0x1100, 0x1f);
    let _ = rc_r_at(base, 0x1100);
    rc_w_at(base, 0x1104, 0x8000_0000 | 0x1100);
    let mut spin = 0u32;
    while rc_r_at(base, 0x1104) & 0x8000_0000 != 0 && spin < 200_000 {
        spin += 1;
    }
    match mdio_read_at(base, 0x1) {
        Some(s) => (s & 0x800 != 0, s & 0x400 != 0),
        None => (false, false),
    }
}

/// Key SERDES/refclk registers of one RC, for the RC1-vs-RC2 comparison dump.
pub struct RcRegs {
    pub hard_debug: u32, // 0x4304 (clkreq/l1ss/iddq/perst)
    pub misc_ctrl: u32,  // 0x4008
    pub status: u32,     // 0x4068 (DL_ACTIVE|PHYLINKUP)
    pub phy_ctl15: u32,  // 0x184c (PM_CLK_PERIOD | DIS_PLL_PD)
    pub link_state: u32, // 0x00bc (FreeBSD link-state; >>16 nonzero = up)
    pub pll_lock: bool,  // SERDES PLL locked (MDIO)
    pub ssc: bool,       // SSC active (MDIO)
}
fn dump_rc(base: usize) -> RcRegs {
    let (pll_lock, ssc) = serdes_pll_at(base);
    RcRegs {
        hard_debug: rc_r_at(base, 0x4304),
        misc_ctrl: rc_r_at(base, 0x4008),
        status: rc_r_at(base, 0x4068),
        phy_ctl15: rc_r_at(base, 0x184c),
        link_state: rc_r_at(base, 0x00bc),
        pll_lock,
        ssc,
    }
}
/// Compare the SERDES/refclk state of the BROKEN external RC1 against the WORKING
/// firmware-trained RC2 (RP1). The register delta pinpoints what firmware did for
/// RC2's refclk/PLL that RC1 is missing — the root cause of RC1's PLL-lock failure.
pub fn refclk_compare() -> (RcRegs, RcRegs) {
    (dump_rc(RC1), dump_rc(RC2))
}

/// Stage 0: is the RC1 link up? (`dtparam=pciex1` → firmware trains it.)
pub fn rc1_status() -> u32 {
    rc_r(PCIE_STATUS)
}
pub fn rc1_link_up() -> bool {
    rc_r(PCIE_STATUS) & LINK_UP_MASK == LINK_UP_MASK
}

// --- P9 Path B: HEQK trains the RC1 link (pcie-brcmstb, BCM2712/BCM7712 path) --
// The firmware trains RC2 (RP1) but NOT RC1, so we replicate brcm_pcie_setup →
// post_setup_bcm2712 → start_link ourselves. RESCAL is skipped (global block,
// already calibrated by firmware for RC2); the per-controller SERDES-PLL refclk
// MDIO is the mandatory piece firmware never ran on RC1 (the cause of PHYLINKUP=0).

const BRIDGE_SET: usize = 0x10_0150_4330; // brcmstb-reset bank1 SET,  BIT(11)=0x800
const BRIDGE_CLR: usize = 0x10_0150_4334; // brcmstb-reset bank1 CLEAR

#[inline]
fn abs_w(addr: usize, v: u32) {
    unsafe { write_volatile(addr as *mut u32, v) };
}

/// Accurate busy-delay via the physical counter (bounded — always terminates).
fn delay_us(us: u64) {
    let freq: u64;
    let start: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start, options(nomem, nostack));
    }
    let ticks = freq.saturating_mul(us) / 1_000_000;
    loop {
        let now: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack)) };
        if now.wrapping_sub(start) >= ticks {
            break;
        }
    }
}

/// One RC1 SERDES-PLL MDIO write (port 0): addr=regad, dummy read, data|DONE, poll.
fn mdio_write(regad: u32, data: u16) {
    rc_w(0x1100, regad); // RC_DL_MDIO_ADDR (write cmd, port 0)
    let _ = rc_r(0x1100); // posted-flush dummy readback (required)
    rc_w(0x1104, 0x8000_0000 | data as u32); // RC_DL_MDIO_WR_DATA: MDIO_WT_DONE | data
    let mut spin = 0u32;
    while rc_r(0x1104) & 0x8000_0000 != 0 && spin < 200_000 {
        spin += 1;
    }
}

/// RC1 bring-up diagnostics (so one flash pinpoints the failing stage).
pub struct RcDiag {
    pub rescal_done: bool, // RESCAL STATUS bit0 after trigger
    pub iddq_before: u32,  // HARD_DEBUG bit27 (1 = SERDES powered DOWN) before
    pub iddq_after: u32,   // ... after clearing it (want 0)
    pub mdio_timeouts: u32, // # of the 8 refclk MDIO writes that timed out (want 0)
    pub perst_before: u32, // PCIE_CTRL bit2 before (0 = in reset)
    pub perst_after: u32,  // ... after de-assert (want 1)
    pub pll_clear: bool,   // PLL locked with clkreq CLEARED (Linux "safe")
    pub pll_set: bool,     // PLL locked with clkreq SET (FreeBSD)
    pub pll_lock: bool,    // SERDES PLL locked (MDIO SSC_STATUS bit11) — PHY alive
    pub ssc: bool,         // SSC active (MDIO SSC_STATUS bit10)
    pub status: u32,       // PCIE_STATUS final (link up iff & 0x30 == 0x30)
}

/// One RC1 SERDES-PLL MDIO write; returns true if the DONE bit cleared (success).
fn mdio_write_ok(regad: u32, data: u16) -> bool {
    rc_w(0x1100, regad);
    let _ = rc_r(0x1100);
    rc_w(0x1104, 0x8000_0000 | data as u32);
    let mut spin = 0u32;
    while rc_r(0x1104) & 0x8000_0000 != 0 {
        spin += 1;
        if spin >= 200_000 {
            return false;
        }
    }
    true
}

/// One RC1 SERDES MDIO READ (port 0): ADDR word carries CMD_READ (1<<20); poll
/// RD_DATA (0x1108) for the DONE flag (bit31), value in the low 31 bits. Mirrors
/// Linux `brcm_pcie_mdio_read`. Returns None on timeout.
fn mdio_read(regad: u32) -> Option<u16> {
    rc_w(0x1100, regad | 0x0010_0000); // MDIO_CMD_READ (1) in the CMD field (bits 20+)
    let _ = rc_r(0x1100); // posted-flush
    let mut spin = 0u32;
    loop {
        let v = rc_r(0x1108); // RC_DL_MDIO_RD_DATA
        if v & 0x8000_0000 != 0 {
            return Some((v & 0xffff) as u16);
        }
        spin += 1;
        if spin >= 200_000 {
            return None;
        }
    }
}

/// Read the SERDES **PLL-lock** (+ SSC) status via MDIO — the only "PHY alive"
/// signal the BCM2712 exposes (there is NO memory-mapped LTSSM state register).
/// Pages in the SSC/status MDIO block (SET_ADDR 0x1f = 0x1100), then reads
/// SSC_STATUS (offset 0x1): PLL_LOCK = bit11 (0x800), SSC = bit10 (0x400).
/// pll_lock=false ⇒ the SerDes PLL never locked ⇒ refclk/PLL problem (RC side);
/// pll_lock=true but link down ⇒ failure is downstream (endpoint/analog/board).
fn serdes_pll_status() -> (bool, bool) {
    mdio_write(0x1f, 0x1100); // SET_ADDR_OFFSET = SSC_REGS_ADDR
    match mdio_read(0x1) {
        // SSC_STATUS_OFFSET
        Some(s) => (s & 0x800 != 0, s & 0x400 != 0),
        None => (false, false),
    }
}

/// Force the RC1 link to **Gen1** before training (many marginal PHYs only train
/// at Gen1). Writes SLS/TLS = 1 (low 4 bits) into LNKCAP + LNKCTL2 in the RC cap
/// block (BRCM_PCIE_CAP_REGS 0x00ac; LNKCAP +0x0c, LNKCTL2 +0x30) — the rpi-6.6.y
/// `brcm_pcie_set_gen` path.
fn force_gen1() {
    let lnkcap = rc_r(0x00b8); // 0x00ac + PCI_EXP_LNKCAP(0x0c)
    rc_w(0x00b8, (lnkcap & !0xf) | 1);
    let lnkctl2 = rc_r(0x00dc); // 0x00ac + PCI_EXP_LNKCTL2(0x30)
    rc_w(0x00dc, (lnkctl2 & !0xf) | 1);
}

/// Train the RC1 link (full sequence incl. RESCAL), with per-stage read-back
/// diagnostics. Link up iff `status & 0x30 == 0x30`.
pub fn rc1_train() -> RcDiag {
    // 0. RESCAL PHY-impedance calibration (global block @ 0x10_0011_9500).
    unsafe {
        let start = 0x10_0011_9500usize;
        let v = read_volatile(start as *const u32);
        write_volatile(start as *mut u32, v | 1); // START
        let mut spin = 0u32;
        while read_volatile((start + 8) as *const u32) & 1 == 0 && spin < 100_000 {
            spin += 1;
        }
        let v2 = read_volatile(start as *const u32);
        write_volatile(start as *mut u32, v2 & !1); // clear START
    }
    let rescal_done = unsafe { read_volatile(0x10_0011_9508 as *const u32) & 1 != 0 };

    // 1. bridge reset cycle (brcmstb-reset block, not the RC's dead 0x9210).
    abs_w(BRIDGE_SET, 0x800);
    delay_us(150);
    abs_w(BRIDGE_CLR, 0x800);
    delay_us(150);
    // 2. SERDES power-up: clear SERDES_IDDQ (bit27) in HARD_DEBUG (2712 @ 0x4304).
    let iddq_before = rc_r(0x4304) & 0x0800_0000;
    rc_w(0x4304, rc_r(0x4304) & !0x0800_0000);
    delay_us(150);
    let iddq_after = rc_r(0x4304) & 0x0800_0000;
    // 3. MISC_CTRL.
    rc_w(0x4008, (rc_r(0x4008) & !0x0030_3480) | 0x0020_3480);
    // 5. refclk MDIO — teach RC1's SERDES PLL the 54 MHz reference.
    let mut mdio_timeouts = 0u32;
    for (a, d) in [
        (0x1fu32, 0x1600u16),
        (0x16, 0x50b9),
        (0x17, 0xbda1),
        (0x18, 0x0094),
        (0x19, 0x97b4),
        (0x1b, 0x5030),
        (0x1c, 0x5030),
        (0x1e, 0x0007),
    ] {
        if !mdio_write_ok(a, d) {
            mdio_timeouts += 1;
        }
    }
    delay_us(150);
    // PM_CLK_PERIOD (0x12 = 18.52 ns @54 MHz) AND disable PLL power-down
    // (DIS_PLL_PD, bit22 0x400000) — a BCM2712 requirement: without it the SERDES
    // PLL can stay powered down and never lock (PHYLINKUP=0). Was missing before.
    rc_w(0x184c, (rc_r(0x184c) & !0xff) | 0x12 | 0x0040_0000);
    // UBUS/AXI error suppression + timeouts.
    rc_w(0x40a4, rc_r(0x40a4) | (1 << 13) | (1 << 19));
    rc_w(0x4170, 0xffff_ffff);
    rc_w(0x40a8, 0x0B2D_0000);
    rc_w(0x405c, 0x0ABA_0000);
    let mut t = rc_r(0x416c);
    t &= !(1 << 7);
    t |= (1 << 13) | (1 << 12) | (1 << 11);
    rc_w(0x416c, t);
    let t2 = rc_r(0x416c);
    if t2 & (1 << 12) == 0 {
        rc_w(0x416c, (t2 & !0x3f) | 15);
    }
    rc_w(0x40a0, rc_r(0x40a0) & !(1 << 5));
    // 7. CLKREQ controversy resolved EMPIRICALLY. Linux `brcm_config_clkreq`
    // "safe" mode CLEARS CLKREQ_DEBUG(0x2)+L1SS(0x200000) → refclk driven
    // unconditionally; FreeBSD's 2711 driver SETS CLKREQ_ENABLE(0x2). They do the
    // OPPOSITE with the same bit. The SERDES PLL locks off the refclk regardless of
    // PERST, so read PLL lock under BOTH settings (L1SS always cleared) and keep
    // whichever locks. This one flash tells us which mode actually drives refclk on
    // this hardwired, floating-CLKREQ# connector.
    rc_w(0x4304, rc_r(0x4304) & !0x0020_0002); // clkreq CLEAR (Linux "safe")
    delay_us(50_000);
    let (pll_clear, _) = serdes_pll_status();
    rc_w(0x4304, (rc_r(0x4304) & !0x0020_0000) | 0x2); // clkreq SET (FreeBSD), L1SS off
    delay_us(50_000);
    let (pll_set, _) = serdes_pll_status();
    // Keep the mode that locked (prefer Linux "safe"=clear on a tie/neither).
    let clkreq_set_wins = pll_set && !pll_clear;
    if clkreq_set_wins {
        rc_w(0x4304, (rc_r(0x4304) & !0x0020_0000) | 0x2);
    } else {
        rc_w(0x4304, rc_r(0x4304) & !0x0020_0002);
    }

    // 7b. Force Gen1 before releasing the endpoint (marginal PHYs train at Gen1).
    force_gen1();

    // 8. PERST# with a settle window (Linux tperst_clk_ms). Hold PERST# externally
    // LOW (HARD_DEBUG PERST_ASSERT bit3 = 0x8) while the internal reset releases,
    // so the SERDES PLL pre-generates a STABLE refclk BEFORE the endpoint leaves
    // reset — then read PLL lock, then release PERST# to the endpoint.
    rc_w(0x4304, rc_r(0x4304) | 0x8); // PERST_ASSERT: force PERST# output low
    let perst_before = rc_r(0x4064) & 0x4;
    rc_w(0x4064, rc_r(0x4064) | 0x4); // internal PERSTB de-assert (bit2 = 1)
    let perst_after = rc_r(0x4064) & 0x4;
    delay_us(200_000); // 200 ms: let the PLL lock on the now-stable refclk
    // DECISIVE DIAGNOSTIC: did the SERDES PLL lock? (read before endpoint release)
    let (pll_lock, ssc) = serdes_pll_status();
    rc_w(0x4304, rc_r(0x4304) & !0x8); // release PERST# to the endpoint
    // 9. CEM 100 ms after PERST# release, then poll link up to +100 ms.
    delay_us(100_000);
    let mut status = rc_r(0x4068);
    for _ in 0..20 {
        status = rc_r(0x4068);
        if status & 0x30 == 0x30 {
            break;
        }
        delay_us(5_000);
    }
    RcDiag {
        rescal_done,
        iddq_before,
        iddq_after,
        mdio_timeouts,
        perst_before,
        perst_after,
        pll_clear,
        pll_set,
        pll_lock,
        ssc,
        status,
    }
}

/// Program RC1's INBOUND DMA window (PCIe bus 0x10_0000_0000 → RAM 0x0, 64 GiB).
/// Byte-for-byte `gem.rs::pcie_inbound_window`, base only differs. Returns the
/// pre-write (RC_BAR1_LO, UBUS_REMAP_LO) to see if firmware already set it.
pub fn pcie_inbound_window() -> (u32, u32) {
    let before = (rc_r(0x402c), rc_r(0x40ac));
    rc_w(0x4008, rc_r(0x4008) | 0x1000); // SCB_ACCESS_EN
    rc_w(0x4030, 0x0000_0010); // RC_BAR1 HI = upper32(0x10_00000000)
    rc_w(0x402c, 0x0000_0015); // RC_BAR1 LO = size code 0x15 (2^36 = 64 GiB)
    rc_w(0x40b0, 0x0000_0000); // UBUS_BAR1 remap HI
    rc_w(0x40ac, 0x0000_0001); // UBUS_BAR1 remap LO | ACCESS_EN
    rc_w(0x40a4, rc_r(0x40a4) | (1 << 13) | (1 << 19)); // UBUS_CTRL err-suppress
    rc_w(0x4170, 0xffff_ffff); // AXI_READ_ERROR_DATA
    before
}

// --- PCIe config space (indirect index/data) ---------------------------------
#[inline]
fn cfg_addr(bus: u32, devfn: u32) {
    rc_w(CFG_INDEX, (bus << 20) | (devfn << 12));
}
pub fn cfg_r32(bus: u32, devfn: u32, reg: usize) -> u32 {
    cfg_addr(bus, devfn);
    unsafe { read_volatile((RC1 + CFG_DATA + (reg & 0xfff)) as *const u32) }
}
pub fn cfg_w32(bus: u32, devfn: u32, reg: usize, v: u32) {
    cfg_addr(bus, devfn);
    unsafe { write_volatile((RC1 + CFG_DATA + (reg & 0xfff)) as *mut u32, v) };
}

const RTL_VENDOR_DEVICE: u32 = 0x8168_10EC; // device 0x8168 | vendor 0x10EC

/// Stage 2-3: set the RC bus numbers, find the RTL at 01:00.0, assign BAR2 into
/// the outbound MMIO window, enable Memory-Space + Bus-Master, and read the MAC.
/// Returns Some(mac) if the RTL is found + configured, else None.
pub fn enumerate() -> Option<[u8; 6]> {
    // RC config (bus0 dev0) reg 0x18: primary=0, secondary=1, subordinate=1.
    cfg_w32(0, 0, 0x18, 0x0001_0100);
    // Downstream 01:00.0 vendor/device.
    if cfg_r32(1, 0, 0x00) != RTL_VENDOR_DEVICE {
        return None;
    }
    // Assign BAR2 = PCIe bus 0x0 (the outbound window base); BAR3 (64-bit hi) = 0.
    cfg_w32(1, 0, 0x18, 0x0000_0000);
    cfg_w32(1, 0, 0x1c, 0x0000_0000);
    // Command reg (0x04): Memory-Space-Enable(bit1) | Bus-Master-Enable(bit2).
    let cmd = cfg_r32(1, 0, 0x04);
    cfg_w32(1, 0, 0x04, cmd | 0x0006);
    // MAC0..5 are eFuse-loaded on the 8111H — read them from BAR2 MMIO.
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = unsafe { read_volatile((RTL_MMIO + i) as *const u8) };
    }
    Some(mac)
}

// --- RTL8111H MAC (BAR2 MMIO @ RTL_MMIO) --------------------------------------
#[inline]
unsafe fn m8(off: usize) -> u8 {
    read_volatile((RTL_MMIO + off) as *const u8)
}
#[inline]
unsafe fn wm8(off: usize, v: u8) {
    write_volatile((RTL_MMIO + off) as *mut u8, v);
}
#[inline]
unsafe fn wm16(off: usize, v: u16) {
    write_volatile((RTL_MMIO + off) as *mut u16, v);
}
#[inline]
unsafe fn wm32(off: usize, v: u32) {
    write_volatile((RTL_MMIO + off) as *mut u32, v);
}

// RTL register offsets.
const CR: usize = 0x37; // ChipCmd: Reset=0x10 RxEnb=0x08 TxEnb=0x04 StopReq=0x80
const TXPOLL: usize = 0x38; // NPQ doorbell = 0x40
const IMR: usize = 0x3C;
const TXCFG: usize = 0x40;
const RXCFG: usize = 0x44;
const CFG9346: usize = 0x50; // Unlock=0xC0 Lock=0x00
const PHYSTATUS: usize = 0x6C; // LinkStatus = 0x02
const RMS: usize = 0xDA;
const CPLUSCMD: usize = 0xE0;
const INTRMIT: usize = 0xE2;
const TNPDS_LO: usize = 0x20;
const TNPDS_HI: usize = 0x24;
const RDSAR_LO: usize = 0xE4;
const RDSAR_HI: usize = 0xE8;

// Descriptor opts1 bits.
const OWN: u32 = 1 << 31; // NIC owns (SW polls for 0, same polarity RX+TX)
const EOR: u32 = 1 << 30; // end of ring (last descriptor)
const FS: u32 = 1 << 29; // first segment
const LS: u32 = 1 << 28; // last segment
const RX_RES: u32 = 1 << 21; // RX error summary
const LEN_MASK: u32 = 0x3FFF;

const NRX: usize = 256;
const NTX: usize = 256;
const RXBUF: usize = 2048;

/// 16-byte RTL descriptor: {opts1, opts2, addr_lo, addr_hi}.
#[repr(C, align(256))]
struct RxRing {
    desc: [[u32; 4]; NRX],
    buf: [[u8; RXBUF]; NRX],
}
#[repr(C, align(256))]
struct TxRing {
    desc: [[u32; 4]; NTX],
    buf: [[u8; RXBUF]; NTX],
}
static mut RX: RxRing = RxRing { desc: [[0; 4]; NRX], buf: [[0; RXBUF]; NRX] };
static mut TX: TxRing = TxRing { desc: [[0; 4]; NTX], buf: [[0; RXBUF]; NTX] };

/// Stage 4: reset the MAC, build the RX ring (buffers' bus addrs = phys+offset,
/// descriptors written via the NC alias), and start RX+TX (polled, IMR=0).
pub fn mac_start() {
    unsafe {
        // Reset.
        wm8(CR, 0x80);
        for _ in 0..100 {
            core::hint::spin_loop();
        }
        wm8(CR, 0x10);
        let mut spin = 0u32;
        while m8(CR) & 0x10 != 0 && spin < 1_000_000 {
            spin += 1;
        }

        // Build the RX ring through the NC alias (descriptors coherent w/ NIC).
        let rx_desc_pa = core::ptr::addr_of!(RX.desc) as usize;
        for i in 0..NRX {
            let bufpa = core::ptr::addr_of!(RX.buf[i]) as usize;
            let bus = bufpa as u64 + DMA_BUS_OFFSET;
            let d = nc_desc(rx_desc_pa + i * 16);
            write_volatile(d.add(0), OWN | if i == NRX - 1 { EOR } else { 0 } | (RXBUF as u32 & LEN_MASK));
            write_volatile(d.add(1), 0);
            write_volatile(d.add(2), bus as u32);
            write_volatile(d.add(3), (bus >> 32) as u32);
        }
        let tx_desc_pa = core::ptr::addr_of!(TX.desc) as usize;
        for i in 0..NTX {
            let d = nc_desc(tx_desc_pa + i * 16);
            write_volatile(d.add(0), if i == NTX - 1 { EOR } else { 0 });
            write_volatile(d.add(1), 0);
            write_volatile(d.add(2), 0);
            write_volatile(d.add(3), 0);
        }
        core::arch::asm!("dsb sy");

        let rx_bus = rx_desc_pa as u64 + DMA_BUS_OFFSET;
        let tx_bus = tx_desc_pa as u64 + DMA_BUS_OFFSET;
        wm8(CFG9346, 0xC0); // unlock
        wm16(CPLUSCMD, 0);
        wm16(INTRMIT, 0);
        wm16(RMS, 0x4000);
        wm32(TNPDS_HI, (tx_bus >> 32) as u32); // HIGH before LOW (source quirk)
        wm32(TNPDS_LO, tx_bus as u32);
        wm32(RDSAR_HI, (rx_bus >> 32) as u32);
        wm32(RDSAR_LO, rx_bus as u32);
        wm8(CFG9346, 0x00); // lock
        let _ = m8(CR); // commit posted writes
        wm8(CR, 0x0C); // RxEnb | TxEnb
        wm32(TXCFG, 0x0300_0780);
        wm32(RXCFG, 0x0000_CF00);
        wm32(0x08, 0xFFFF_FFFF); // MAR0 all-multicast
        wm32(0x0C, 0xFFFF_FFFF);
        wm32(RXCFG, (read_volatile((RTL_MMIO + RXCFG) as *const u32) & !0xF) | 0x0E); // B|MyPhys|Mcast
        wm16(IMR as usize, 0); // polled
    }
}

pub fn link_up() -> bool {
    unsafe { m8(PHYSTATUS) & 0x02 != 0 }
}

/// Poll RX descriptor `i`: returns Some((desc_index, len)) with the frame copied
/// into `out`, or None if the NIC still owns it / it errored. Re-arms the slot.
pub fn poll_rx(i: usize, out: &mut [u8]) -> Option<usize> {
    let rx_desc_pa = unsafe { core::ptr::addr_of!(RX.desc) } as usize;
    let d = nc_desc(rx_desc_pa + i * 16);
    let opts1 = unsafe { read_volatile(d.add(0)) };
    if opts1 & OWN != 0 {
        return None; // NIC still owns it
    }
    let mut result = None;
    if opts1 & RX_RES == 0 {
        let len = ((opts1 & LEN_MASK) as usize).saturating_sub(4); // strip FCS
        let n = len.min(out.len());
        let bufpa = unsafe { core::ptr::addr_of!(RX.buf[i]) } as usize;
        unsafe {
            // Buffers are cacheable — invalidate before reading the NIC's write.
            let mut a = bufpa & !63;
            while a < bufpa + n {
                core::arch::asm!("dc ivac, {}", in(reg) a);
                a += 64;
            }
            core::arch::asm!("dsb sy");
            core::ptr::copy_nonoverlapping(bufpa as *const u8, out.as_mut_ptr(), n);
        }
        result = Some(len);
    }
    // Re-arm: set OWN (no doorbell needed for RX).
    unsafe {
        write_volatile(d.add(0), OWN | if i == NRX - 1 { EOR } else { 0 } | (RXBUF as u32 & LEN_MASK));
        core::arch::asm!("dsb sy");
    }
    result
}

/// Stage 5: transmit one frame via TX descriptor 0 + the NPQ doorbell; polls
/// OWN-cleared. Returns true on completion.
pub fn tx_frame(frame: &[u8]) -> bool {
    let n = frame.len().min(RXBUF);
    unsafe {
        let tx_desc_pa = core::ptr::addr_of!(TX.desc) as usize;
        let bufpa = core::ptr::addr_of!(TX.buf[0]) as usize;
        core::ptr::copy_nonoverlapping(frame.as_ptr(), bufpa as *mut u8, n);
        // Clean the buffer to DRAM for the NIC.
        let mut a = bufpa & !63;
        while a < bufpa + n {
            core::arch::asm!("dc cvac, {}", in(reg) a);
            a += 64;
        }
        core::arch::asm!("dsb sy");
        let bus = bufpa as u64 + DMA_BUS_OFFSET;
        let d = nc_desc(tx_desc_pa);
        write_volatile(d.add(2), bus as u32);
        write_volatile(d.add(3), (bus >> 32) as u32);
        write_volatile(d.add(1), 0);
        write_volatile(d.add(0), OWN | FS | LS | EOR | (n as u32 & LEN_MASK));
        core::arch::asm!("dsb sy");
        wm8(TXPOLL, 0x40); // NPQ doorbell
        let mut spin = 0u32;
        while read_volatile(d.add(0)) & OWN != 0 && spin < 1_000_000 {
            spin += 1;
        }
        read_volatile(d.add(0)) & OWN == 0
    }
}
