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

/// Stage 0: is the RC1 link up? (`dtparam=pciex1` → firmware trains it.)
pub fn rc1_status() -> u32 {
    rc_r(PCIE_STATUS)
}
pub fn rc1_link_up() -> bool {
    rc_r(PCIE_STATUS) & LINK_UP_MASK == LINK_UP_MASK
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
