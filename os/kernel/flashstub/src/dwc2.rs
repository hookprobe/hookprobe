// SPDX-License-Identifier: AGPL-3.0-only
//! Synopsys DesignWare USB 2.0 OTG ("DWC2") core in DEVICE mode — the BCM2712's own OTG controller (`usb@480000`,
//! base 0x10_0048_0000, ADR 0070 D6). Slave (FIFO / PIO) mode, polled: no DMA, no interrupt (GAHBCFG.GINTMSK stays 0
//! and the CPU runs with IRQs masked; the per-source mask registers are programmed only so the status registers
//! latch the same events an interrupt-driven driver would see).
//!
//! Scope: EP0 control (chapter-9 standard requests, the vendor request for the MS OS 2.0 descriptor set), one bulk
//! OUT endpoint and one bulk IN endpoint. One bulk OUT transfer = one HQFL frame (it ends in a short packet: no HQFL
//! frame length is a multiple of 512), one bulk IN transfer = one response.
//!
//! Provenance (ADR 0067 D11): written from the USB 2.0 specification (chapter 9) and the DWC2 programming model
//! (register offsets, bit positions, the slave-mode RX status codes, the core-reset handshake) — hardware facts.
//! No upstream driver source was opened while writing it. The only code reference ADR 0070 D6 permits is TinyUSB's
//! `src/portable/synopsys/dwc2` (MIT); Linux `drivers/usb/dwc2` (GPL-2.0) is not to be transcribed. Registered in
//! docs/security/driver-provenance.md.
//!
//! Everything metal must confirm is listed in `Dwc2::init`'s comment and the stub's PR: the controller identity
//! (GSNPSID), the PHY the firmware left selected, the FIFO RAM depth, and dedicated versus shared TX FIFOs.

/// Register access, so the host tests can run this exact driver against a register-level model.
pub trait Regs {
    fn read(&mut self, off: usize) -> u32;
    fn write(&mut self, off: usize, val: u32);
    fn delay_us(&mut self, us: u32);
}

// ── register offsets ──────────────────────────────────────────────────────────────────────────────
pub const GOTGCTL: usize = 0x000;
pub const GAHBCFG: usize = 0x008;
pub const GUSBCFG: usize = 0x00C;
pub const GRSTCTL: usize = 0x010;
pub const GINTSTS: usize = 0x014;
pub const GINTMSK: usize = 0x018;
pub const GRXSTSP: usize = 0x020;
pub const GRXFSIZ: usize = 0x024;
pub const GNPTXFSIZ: usize = 0x028; // = DIEPTXF0 with dedicated FIFOs
pub const GNPTXSTS: usize = 0x02C;
pub const GSNPSID: usize = 0x040;
pub const GHWCFG1: usize = 0x044;
pub const GHWCFG2: usize = 0x048;
pub const GHWCFG3: usize = 0x04C;
pub const GHWCFG4: usize = 0x050;
pub const DIEPTXF1: usize = 0x104;
pub const DCFG: usize = 0x800;
pub const DCTL: usize = 0x804;
pub const DSTS: usize = 0x808;
pub const DIEPMSK: usize = 0x810;
pub const DOEPMSK: usize = 0x814;
pub const DAINT: usize = 0x818;
pub const DAINTMSK: usize = 0x81C;
pub const PCGCCTL: usize = 0xE00;
pub const fn diepctl(n: usize) -> usize {
    0x900 + 0x20 * n
}
pub const fn diepint(n: usize) -> usize {
    0x908 + 0x20 * n
}
pub const fn dieptsiz(n: usize) -> usize {
    0x910 + 0x20 * n
}
pub const fn dtxfsts(n: usize) -> usize {
    0x918 + 0x20 * n
}
pub const fn doepctl(n: usize) -> usize {
    0xB00 + 0x20 * n
}
pub const fn doepint(n: usize) -> usize {
    0xB08 + 0x20 * n
}
pub const fn doeptsiz(n: usize) -> usize {
    0xB10 + 0x20 * n
}
/// Endpoint n's FIFO window (IN: push for endpoint n; any window pops the shared RX FIFO).
pub const fn fifo(n: usize) -> usize {
    0x1000 * (n + 1)
}

// ── bits ──────────────────────────────────────────────────────────────────────────────────────────
pub const GUSBCFG_PHYIF16: u32 = 1 << 3;
pub const GUSBCFG_ULPI: u32 = 1 << 4;
pub const GUSBCFG_PHYSEL_FS: u32 = 1 << 6;
pub const GUSBCFG_TRDT_SHIFT: u32 = 10;
pub const GUSBCFG_TRDT_MASK: u32 = 0xF << 10;
pub const GUSBCFG_FHMOD: u32 = 1 << 29;
pub const GUSBCFG_FDMOD: u32 = 1 << 30;

pub const GRSTCTL_CSRST: u32 = 1 << 0;
pub const GRSTCTL_RXFFLSH: u32 = 1 << 4;
pub const GRSTCTL_TXFFLSH: u32 = 1 << 5;
pub const GRSTCTL_TXFNUM_ALL: u32 = 0x10 << 6;
/// Cores from 4.20a: the soft reset is done when this reads 1 (CSRST no longer self-clears).
pub const GRSTCTL_CSRST_DONE: u32 = 1 << 29;
pub const GRSTCTL_AHBIDL: u32 = 1 << 31;

pub const GINTSTS_RXFLVL: u32 = 1 << 4;
pub const GINTSTS_USBSUSP: u32 = 1 << 11;
pub const GINTSTS_USBRST: u32 = 1 << 12;
pub const GINTSTS_ENUMDNE: u32 = 1 << 13;
pub const GINTSTS_IEPINT: u32 = 1 << 18;
pub const GINTSTS_OEPINT: u32 = 1 << 19;

pub const DCTL_SFTDISCON: u32 = 1 << 1;
pub const DCTL_CGINAK: u32 = 1 << 8;
pub const DCTL_CGONAK: u32 = 1 << 10;
pub const DCFG_DAD_SHIFT: u32 = 4;
pub const DCFG_DAD_MASK: u32 = 0x7F << 4;
pub const DCFG_DSPD_MASK: u32 = 0x3;

pub const EPCTL_MPS_MASK: u32 = 0x7FF;
pub const EPCTL_USBACTEP: u32 = 1 << 15;
pub const EPCTL_NAKSTS: u32 = 1 << 17;
pub const EPCTL_TYPE_BULK: u32 = 2 << 18;
pub const EPCTL_STALL: u32 = 1 << 21;
pub const EPCTL_TXFNUM_SHIFT: u32 = 22;
pub const EPCTL_CNAK: u32 = 1 << 26;
pub const EPCTL_SNAK: u32 = 1 << 27;
pub const EPCTL_SD0PID: u32 = 1 << 28;
pub const EPCTL_EPDIS: u32 = 1 << 30;
pub const EPCTL_EPENA: u32 = 1 << 31;

pub const EPINT_XFERCOMPL: u32 = 1 << 0;
pub const EPINT_EPDISBLD: u32 = 1 << 1;
pub const DOEPINT_SETUP: u32 = 1 << 3;
pub const DIEPINT_TIMEOUT: u32 = 1 << 3;

pub const TSIZ_PKTCNT_SHIFT: u32 = 19;
pub const DOEPTSIZ0_SUPCNT3: u32 = 3 << 29;

// GRXSTSP packet status (device mode)
pub const PKT_OUT_NAK: u32 = 1;
pub const PKT_OUT_DATA: u32 = 2;
pub const PKT_OUT_DONE: u32 = 3;
pub const PKT_SETUP_DONE: u32 = 4;
pub const PKT_SETUP_DATA: u32 = 6;

/// FIFO RAM plan, in 32-bit words. RX: room for two 512-byte packets with their status words, three SETUPs and the
/// transfer-complete entries. TX: EP0 one 64-byte packet; the bulk IN endpoint two 512-byte packets.
pub const RX_FIFO_WORDS: u32 = 288;
pub const EP0_TX_WORDS: u32 = 16;
pub const BULK_TX_WORDS: u32 = 256;

use crate::desc;

/// Why the core was not brought up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitErr {
    /// GSNPSID does not read 0x4F54_xxxx: not a DWC2 core (or not powered / clocked). Nothing was written.
    NotDwc2(u32),
    /// The core has fewer than two device endpoints besides EP0.
    TooFewEndpoints(u32),
    /// The FIFO RAM (GHWCFG3) is smaller than the plan above.
    FifoTooSmall(u32),
    /// A GRSTCTL handshake never completed (AHB idle, core reset, FIFO flush).
    ResetTimeout(u32),
}

/// The hardware configuration read at init (the first metal read: ADR 0070 M2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HwInfo {
    pub snpsid: u32,
    pub hwcfg: [u32; 4],
    pub gusbcfg_at_entry: u32,
    pub fifo_words: u32,
    pub dev_eps: u32,
    pub dedicated_fifos: bool,
    pub phy_16bit: bool,
}

impl HwInfo {
    /// HS PHY type (GHWCFG2[7:6]): 0 none, 1 UTMI+, 2 ULPI, 3 both.
    pub fn hs_phy(&self) -> u32 {
        (self.hwcfg[1] >> 6) & 3
    }
    /// Architecture (GHWCFG2[4:3]): 0 slave only, 1 external DMA, 2 internal DMA.
    pub fn arch(&self) -> u32 {
        (self.hwcfg[1] >> 3) & 3
    }
}

/// What `poll` saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// USB bus reset: the host (re)starts enumeration; any session is over.
    Reset,
    /// Enumeration finished at this speed.
    Enumerated { high_speed: bool },
    /// SET_CONFIGURATION(1): the bulk endpoints are live.
    Configured,
    /// The bus went idle (cable pulled, host suspended).
    Suspend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ep0 {
    Idle,
    /// Sending `ctl[pos..len]` in 64-byte packets; `zlp` = end with a zero-length packet.
    DataIn,
    /// Waiting for the host's zero-length status OUT.
    StatusOut,
    /// Our zero-length status IN is queued.
    StatusIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutSt {
    Idle,
    Armed,
    Done,
}

/// Driver counters (log + tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbStats {
    pub resets: u32,
    pub setups: u32,
    pub stalls: u32,
    pub out_frames: u32,
    pub out_overflow: u32,
    pub in_frames: u32,
}

pub const IN_BUF: usize = 128;

pub struct Dwc2<'a, R: Regs> {
    r: R,
    pub hw: HwInfo,
    high_speed: bool,
    config: u8,
    ep0: Ep0,
    setup: [u8; 8],
    setup_ready: bool,
    ctl: [u8; 256],
    ctl_len: usize,
    ctl_pos: usize,
    ctl_zlp: bool,
    /// Bytes of the current EP0 IN packet still to push into the FIFO (None = pushed).
    ctl_pkt: Option<usize>,
    /// Address to apply when the SET_ADDRESS status stage completes (the core already uses DCFG at once; kept for
    /// the log).
    addr: u8,
    out_buf: &'a mut [u8],
    out_len: usize,
    out_st: OutSt,
    in_buf: [u8; IN_BUF],
    in_len: usize,
    in_pushed: usize,
    in_busy: bool,
    halted: [bool; 2], // [OUT, IN]
    serial: [u8; 21],
    pub stats: UsbStats,
}

impl<'a, R: Regs> Dwc2<'a, R> {
    /// Read the identity registers WITHOUT writing anything (the first metal read).
    pub fn identify(r: &mut R) -> HwInfo {
        let snpsid = r.read(GSNPSID);
        let hwcfg = [r.read(GHWCFG1), r.read(GHWCFG2), r.read(GHWCFG3), r.read(GHWCFG4)];
        HwInfo {
            snpsid,
            hwcfg,
            gusbcfg_at_entry: r.read(GUSBCFG),
            fifo_words: hwcfg[2] >> 16,
            dev_eps: (hwcfg[1] >> 10) & 0xF,
            dedicated_fifos: hwcfg[3] & (1 << 25) != 0,
            phy_16bit: false,
        }
    }

    /// True for a DWC2 ("OT") core ID.
    pub fn is_dwc2(snpsid: u32) -> bool {
        snpsid >> 16 == 0x4F54
    }

    /// Bring the core up in device mode and connect.
    ///
    /// Order: identify (refuse a non-DWC2 ID before any write) -> soft-disconnect (so the host sees a fresh device
    /// after the boot ROM's / firmware's own use of the core) -> core soft reset -> force device mode, keeping the
    /// PHY selection the firmware left (UTMI+ / ULPI, 8 / 16 bit: the rpiboot transfer just ran over it) -> FIFO RAM
    /// plan -> flush -> all endpoints NAKed -> soft-connect.
    ///
    /// Metal must confirm: GSNPSID 0x4F54_xxxx; GHWCFG2 HS PHY != 0 and >= 2 device endpoints; GHWCFG3 FIFO depth
    /// >= 560 words; whether GHWCFG4 reports dedicated TX FIFOs (both modes are implemented); that GUSBCFG's PHY
    /// bits as left by the firmware are right for device mode.
    pub fn init(mut r: R, out_buf: &'a mut [u8], build: &[u8; 32]) -> Result<Self, (InitErr, HwInfo)> {
        let mut hw = Self::identify(&mut r);
        if !Self::is_dwc2(hw.snpsid) {
            return Err((InitErr::NotDwc2(hw.snpsid), hw));
        }
        if hw.dev_eps < 2 {
            return Err((InitErr::TooFewEndpoints(hw.dev_eps), hw));
        }
        let need = RX_FIFO_WORDS + EP0_TX_WORDS + BULK_TX_WORDS;
        if hw.fifo_words < need {
            return Err((InitErr::FifoTooSmall(hw.fifo_words), hw));
        }
        // Soft-disconnect first: the host drops whatever it enumerated on this port.
        let dctl = r.read(DCTL);
        r.write(DCTL, dctl | DCTL_SFTDISCON);
        r.delay_us(3000);

        // Core soft reset (AHB idle before and after).
        wait(&mut r, GRSTCTL, GRSTCTL_AHBIDL, true).map_err(|e| (e, hw))?;
        r.write(GRSTCTL, GRSTCTL_CSRST);
        let mut done = false;
        for _ in 0..100_000 {
            let v = r.read(GRSTCTL);
            if v & GRSTCTL_CSRST_DONE != 0 {
                r.write(GRSTCTL, (v & !GRSTCTL_CSRST) | GRSTCTL_CSRST_DONE); // 4.20a+: acknowledge
                done = true;
                break;
            }
            if v & GRSTCTL_CSRST == 0 {
                done = true;
                break;
            }
            r.delay_us(1);
        }
        if !done {
            return Err((InitErr::ResetTimeout(r.read(GRSTCTL)), hw));
        }
        wait(&mut r, GRSTCTL, GRSTCTL_AHBIDL, true).map_err(|e| (e, hw))?;
        r.delay_us(3000);

        // Force device mode with the PHY the firmware selected; turnaround 9 (8-bit UTMI+) or 5 (16-bit).
        let keep = hw.gusbcfg_at_entry & (GUSBCFG_PHYIF16 | GUSBCFG_ULPI | GUSBCFG_PHYSEL_FS | 0x7);
        hw.phy_16bit = keep & GUSBCFG_PHYIF16 != 0;
        let trdt = if hw.phy_16bit { 5 } else { 9 };
        let cfg = (r.read(GUSBCFG) & !(GUSBCFG_PHYIF16 | GUSBCFG_ULPI | GUSBCFG_PHYSEL_FS | 0x7 | GUSBCFG_TRDT_MASK | GUSBCFG_FHMOD))
            | keep
            | (trdt << GUSBCFG_TRDT_SHIFT)
            | GUSBCFG_FDMOD;
        r.write(GUSBCFG, cfg);
        r.delay_us(25_000); // a forced mode change takes effect within 25 ms
        r.write(PCGCCTL, 0); // clocks ungated
        r.write(GAHBCFG, 0); // slave mode, no global interrupt (polled)

        // The reset may have cleared the soft disconnect: stay off the bus while configuring.
        let dctl = r.read(DCTL);
        r.write(DCTL, dctl | DCTL_SFTDISCON);
        // High speed, address 0.
        let dcfg = r.read(DCFG) & !(DCFG_DSPD_MASK | DCFG_DAD_MASK);
        r.write(DCFG, dcfg);

        // FIFO RAM: RX | EP0 TX | bulk IN TX (dedicated FIFO 1), or RX | one shared non-periodic TX FIFO.
        r.write(GRXFSIZ, RX_FIFO_WORDS);
        if hw.dedicated_fifos {
            r.write(GNPTXFSIZ, (EP0_TX_WORDS << 16) | RX_FIFO_WORDS);
            r.write(DIEPTXF1, (BULK_TX_WORDS << 16) | (RX_FIFO_WORDS + EP0_TX_WORDS));
        } else {
            r.write(GNPTXFSIZ, ((EP0_TX_WORDS + BULK_TX_WORDS) << 16) | RX_FIFO_WORDS);
        }
        flush(&mut r, GRSTCTL_TXFFLSH | GRSTCTL_TXFNUM_ALL).map_err(|e| (e, hw))?;
        flush(&mut r, GRSTCTL_RXFFLSH).map_err(|e| (e, hw))?;

        // Every endpoint disabled and NAKing, every endpoint interrupt cleared.
        let n = (hw.dev_eps as usize).min(15);
        for ep in 0..=n {
            for (ctl, int) in [(diepctl(ep), diepint(ep)), (doepctl(ep), doepint(ep))] {
                let v = r.read(ctl);
                if ep != 0 && v & EPCTL_EPENA != 0 {
                    r.write(ctl, EPCTL_EPDIS | EPCTL_SNAK);
                } else {
                    r.write(ctl, EPCTL_SNAK);
                }
                r.write(int, 0xFFFF);
            }
            r.write(dieptsiz(ep), 0);
            r.write(doeptsiz(ep), 0);
        }
        // Latch the events this driver polls (the global interrupt stays off).
        r.write(DIEPMSK, EPINT_XFERCOMPL | DIEPINT_TIMEOUT);
        r.write(DOEPMSK, EPINT_XFERCOMPL | DOEPINT_SETUP);
        r.write(DAINTMSK, 1 | (1 << desc::EP_IN) | (1 << 16) | (1 << (16 + desc::EP_OUT)));
        r.write(GINTSTS, 0xFFFF_FFFF);
        r.write(GINTMSK, GINTSTS_USBRST | GINTSTS_ENUMDNE | GINTSTS_RXFLVL | GINTSTS_IEPINT | GINTSTS_OEPINT | GINTSTS_USBSUSP);

        let mut serial = [0u8; 21];
        desc::serial(build, &mut serial);
        let mut d = Dwc2 {
            r,
            hw,
            high_speed: true,
            config: 0,
            ep0: Ep0::Idle,
            setup: [0; 8],
            setup_ready: false,
            ctl: [0; 256],
            ctl_len: 0,
            ctl_pos: 0,
            ctl_zlp: false,
            ctl_pkt: None,
            addr: 0,
            out_buf,
            out_len: 0,
            out_st: OutSt::Idle,
            in_buf: [0; IN_BUF],
            in_len: 0,
            in_pushed: 0,
            in_busy: false,
            halted: [false; 2],
            serial,
            stats: UsbStats::default(),
        };
        // Soft-connect: the host sees a new device and resets the bus.
        let dctl = d.r.read(DCTL);
        d.r.write(DCTL, dctl & !DCTL_SFTDISCON);
        Ok(d)
    }

    pub fn regs(&mut self) -> &mut R {
        &mut self.r
    }
    pub fn configured(&self) -> bool {
        self.config != 0
    }
    pub fn high_speed(&self) -> bool {
        self.high_speed
    }
    pub fn address(&self) -> u8 {
        self.addr
    }
    pub fn serial(&self) -> &str {
        core::str::from_utf8(&self.serial).unwrap_or("")
    }

    fn bulk_mps(&self) -> u32 {
        if self.high_speed {
            desc::HS_BULK_MPS as u32
        } else {
            desc::FS_BULK_MPS as u32
        }
    }

    /// Service the core once. Returns the most significant bus event seen, if any.
    pub fn poll(&mut self) -> Option<Event> {
        let mut ev = None;
        let st = self.r.read(GINTSTS);
        if st & GINTSTS_USBRST != 0 {
            self.r.write(GINTSTS, GINTSTS_USBRST);
            self.bus_reset();
            ev = Some(Event::Reset);
        }
        if st & GINTSTS_ENUMDNE != 0 {
            self.r.write(GINTSTS, GINTSTS_ENUMDNE);
            self.enum_done();
            if ev.is_none() {
                ev = Some(Event::Enumerated { high_speed: self.high_speed });
            }
        }
        if st & GINTSTS_USBSUSP != 0 {
            self.r.write(GINTSTS, GINTSTS_USBSUSP);
            if ev.is_none() {
                ev = Some(Event::Suspend);
            }
        }
        // Drain the RX FIFO (SETUP packets, OUT data, completion markers).
        for _ in 0..64 {
            if self.r.read(GINTSTS) & GINTSTS_RXFLVL == 0 {
                break;
            }
            self.rx_pop();
        }
        let st = self.r.read(GINTSTS);
        if st & GINTSTS_OEPINT != 0 {
            if let Some(e) = self.out_eps() {
                ev = ev.or(Some(e));
            }
        }
        if st & GINTSTS_IEPINT != 0 {
            self.in_eps();
        }
        self.push_ep0();
        self.push_bulk();
        ev
    }

    fn bus_reset(&mut self) {
        self.stats.resets += 1;
        flush(&mut self.r, GRSTCTL_TXFFLSH | GRSTCTL_TXFNUM_ALL).ok();
        for ep in [0usize, desc::EP_OUT as usize, desc::EP_IN as usize] {
            let v = self.r.read(doepctl(ep));
            self.r.write(doepctl(ep), (v & !EPCTL_EPENA) | EPCTL_SNAK);
            self.r.write(doepint(ep), 0xFFFF);
            self.r.write(diepint(ep), 0xFFFF);
        }
        // Bulk endpoints inactive until SET_CONFIGURATION.
        self.r.write(diepctl(desc::EP_IN as usize), EPCTL_SNAK);
        self.r.write(doepctl(desc::EP_OUT as usize), EPCTL_SNAK);
        let dcfg = self.r.read(DCFG) & !DCFG_DAD_MASK;
        self.r.write(DCFG, dcfg);
        self.config = 0;
        self.addr = 0;
        self.ep0 = Ep0::Idle;
        self.ctl_pkt = None;
        self.setup_ready = false;
        self.out_st = OutSt::Idle;
        self.out_len = 0;
        self.in_busy = false;
        self.halted = [false; 2];
        self.arm_setup();
    }

    fn enum_done(&mut self) {
        let spd = (self.r.read(DSTS) >> 1) & 3;
        self.high_speed = spd == 0;
        // EP0 max packet 64 (MPS encoding 0), clear the global IN NAK.
        let v = self.r.read(diepctl(0));
        self.r.write(diepctl(0), v & !3);
        let d = self.r.read(DCTL);
        self.r.write(DCTL, d | DCTL_CGINAK);
    }

    /// EP0 OUT ready for up to three back-to-back SETUP packets.
    fn arm_setup(&mut self) {
        self.r.write(doeptsiz(0), DOEPTSIZ0_SUPCNT3 | (1 << TSIZ_PKTCNT_SHIFT) | 24);
    }

    fn rx_pop(&mut self) {
        let s = self.r.read(GRXSTSP);
        let ep = (s & 0xF) as usize;
        let bcnt = ((s >> 4) & 0x7FF) as usize;
        let pkt = (s >> 17) & 0xF;
        match pkt {
            PKT_SETUP_DATA => {
                let mut w = [0u8; 8];
                self.read_fifo(&mut w, bcnt.min(8));
                if bcnt > 8 {
                    self.discard_fifo(bcnt - 8);
                }
                self.setup = w;
            }
            PKT_SETUP_DONE => self.setup_ready = true,
            PKT_OUT_DATA if ep == desc::EP_OUT as usize => {
                let room = self.out_buf.len() - self.out_len;
                if bcnt <= room {
                    let (o, n) = (self.out_len, bcnt);
                    let mut i = 0;
                    while i < n {
                        let v = self.r.read(fifo(0)).to_le_bytes();
                        let k = (n - i).min(4);
                        self.out_buf[o + i..o + i + k].copy_from_slice(&v[..k]);
                        i += 4;
                    }
                    self.out_len += n;
                } else {
                    self.stats.out_overflow += 1;
                    self.discard_fifo(bcnt);
                }
            }
            PKT_OUT_DATA => self.discard_fifo(bcnt), // EP0 OUT data (status stage ZLP, or data we do not accept)
            _ => {} // PKT_OUT_DONE, PKT_OUT_NAK: no data
        }
    }

    fn read_fifo(&mut self, out: &mut [u8], n: usize) {
        let mut i = 0;
        while i < n {
            let v = self.r.read(fifo(0)).to_le_bytes();
            let k = (n - i).min(4);
            out[i..i + k].copy_from_slice(&v[..k]);
            i += 4;
        }
    }

    fn discard_fifo(&mut self, n: usize) {
        for _ in 0..n.div_ceil(4) {
            let _ = self.r.read(fifo(0));
        }
    }

    fn out_eps(&mut self) -> Option<Event> {
        let daint = self.r.read(DAINT);
        let mut ev = None;
        if daint & (1 << 16) != 0 {
            let i = self.r.read(doepint(0));
            self.r.write(doepint(0), i);
            if i & EPINT_XFERCOMPL != 0 && self.ep0 == Ep0::StatusOut {
                self.ep0 = Ep0::Idle;
                self.arm_setup();
            }
            if i & DOEPINT_SETUP != 0 || self.setup_ready {
                self.setup_ready = false;
                ev = self.handle_setup();
            }
        }
        let bit = 1 << (16 + desc::EP_OUT as u32);
        if daint & bit != 0 {
            let n = desc::EP_OUT as usize;
            let i = self.r.read(doepint(n));
            self.r.write(doepint(n), i);
            if i & EPINT_XFERCOMPL != 0 && self.out_st == OutSt::Armed {
                self.out_st = OutSt::Done;
                self.stats.out_frames += 1;
            }
        }
        ev
    }

    fn in_eps(&mut self) {
        let daint = self.r.read(DAINT);
        if daint & 1 != 0 {
            let i = self.r.read(diepint(0));
            self.r.write(diepint(0), i);
            if i & EPINT_XFERCOMPL != 0 {
                match self.ep0 {
                    Ep0::DataIn => {
                        if self.ctl_pos < self.ctl_len {
                            self.start_ep0_packet();
                        } else if self.ctl_zlp {
                            self.ctl_zlp = false;
                            self.start_ep0_packet();
                        } else {
                            // Data stage done: the host's zero-length status OUT follows.
                            self.ep0 = Ep0::StatusOut;
                            self.r.write(doeptsiz(0), DOEPTSIZ0_SUPCNT3 | (1 << TSIZ_PKTCNT_SHIFT) | 64);
                            let v = self.r.read(doepctl(0));
                            self.r.write(doepctl(0), v | EPCTL_EPENA | EPCTL_CNAK);
                        }
                    }
                    Ep0::StatusIn => {
                        self.ep0 = Ep0::Idle;
                        self.arm_setup();
                    }
                    _ => {}
                }
            }
        }
        let n = desc::EP_IN as usize;
        if daint & (1 << n) != 0 {
            let i = self.r.read(diepint(n));
            self.r.write(diepint(n), i);
            if i & EPINT_XFERCOMPL != 0 && self.in_busy && self.in_pushed == self.in_len {
                self.in_busy = false;
                self.stats.in_frames += 1;
            }
        }
    }

    // ── EP0 control ───────────────────────────────────────────────────────────────────────────

    fn handle_setup(&mut self) -> Option<Event> {
        self.stats.setups += 1;
        let s = self.setup;
        let (bm, req) = (s[0], s[1]);
        let value = u16::from_le_bytes([s[2], s[3]]);
        let index = u16::from_le_bytes([s[4], s[5]]);
        let length = u16::from_le_bytes([s[6], s[7]]) as usize;
        // A new SETUP aborts whatever EP0 was doing.
        self.ep0 = Ep0::Idle;
        self.ctl_pkt = None;
        self.arm_setup();
        let mut ev = None;
        match (bm, req) {
            // GET_STATUS: device (self-powered), interface, endpoint (halt bit)
            (0x80, 0x00) => self.reply(&[1, 0], length),
            (0x81, 0x00) => self.reply(&[0, 0], length),
            (0x82, 0x00) => match self.ep_index(index) {
                Some(k) => self.reply(&[self.halted[k] as u8, 0], length),
                None if index & 0x7F == 0 => self.reply(&[0, 0], length),
                None => self.stall(),
            },
            // CLEAR_FEATURE / SET_FEATURE (ENDPOINT_HALT) on a bulk endpoint; device features accepted, ignored
            (0x02, 0x01) | (0x02, 0x03) if value == 0 => match self.ep_index(index) {
                Some(k) => {
                    self.set_halt(k, req == 0x03);
                    self.status_in();
                }
                None if index & 0x7F == 0 => self.status_in(),
                None => self.stall(),
            },
            (0x00, 0x01) | (0x00, 0x03) if value == 1 => self.status_in(), // DEVICE_REMOTE_WAKEUP
            // SET_ADDRESS: DCFG.DAD now; the core answers the status stage from address 0.
            (0x00, 0x05) if value < 128 && index == 0 && length == 0 => {
                let d = self.r.read(DCFG) & !DCFG_DAD_MASK;
                self.r.write(DCFG, d | ((value as u32) << DCFG_DAD_SHIFT));
                self.addr = value as u8;
                self.status_in();
            }
            (0x80, 0x06) => self.get_descriptor(value, length),
            (0x80, 0x08) => self.reply(&[self.config], length),
            (0x00, 0x09) if value <= 1 => {
                self.set_configuration(value as u8);
                self.status_in();
                if value == 1 {
                    ev = Some(Event::Configured);
                }
            }
            (0x81, 0x0A) if self.config != 0 && index == 0 => self.reply(&[0], length),
            (0x01, 0x0B) if self.config != 0 && index == 0 && value == 0 => self.status_in(),
            // Microsoft OS 2.0 descriptor set (vendor, device-to-host, wIndex 7)
            (0xC0, desc::MS_VENDOR_CODE) if index == desc::MS_OS_20_DESCRIPTOR_INDEX => {
                self.reply(&desc::MSOS20_SET, length)
            }
            _ => self.stall(),
        }
        ev
    }

    fn get_descriptor(&mut self, value: u16, length: usize) {
        let (ty, idx) = ((value >> 8) as u8, (value & 0xff) as u8);
        match ty {
            1 => self.reply(&desc::DEVICE, length),
            2 => {
                let c = desc::config(2, self.bulk_mps() as u16);
                self.reply(&c, length)
            }
            3 => {
                let mut b = [0u8; 64];
                let serial = self.serial;
                match desc::string(idx, core::str::from_utf8(&serial).unwrap_or(""), &mut b) {
                    Some(n) => self.reply(&b[..n], length),
                    None => self.stall(),
                }
            }
            6 => self.reply(&desc::QUALIFIER, length),
            7 => {
                let other = if self.high_speed { desc::FS_BULK_MPS } else { desc::HS_BULK_MPS };
                let c = desc::config(7, other);
                self.reply(&c, length)
            }
            0x0F => self.reply(&desc::BOS, length),
            _ => self.stall(),
        }
    }

    /// Index into `halted` for a bulk endpoint address (0x01 -> OUT, 0x82 -> IN).
    fn ep_index(&self, index: u16) -> Option<usize> {
        match index as u8 {
            a if a == desc::EP_OUT => Some(0),
            a if a == 0x80 | desc::EP_IN => Some(1),
            _ => None,
        }
    }

    fn set_halt(&mut self, k: usize, on: bool) {
        self.halted[k] = on;
        let reg = if k == 0 { doepctl(desc::EP_OUT as usize) } else { diepctl(desc::EP_IN as usize) };
        let v = self.r.read(reg) & !(EPCTL_EPENA | EPCTL_EPDIS);
        if on {
            self.r.write(reg, v | EPCTL_STALL);
        } else {
            // CLEAR_FEATURE(HALT) also resets the data toggle to DATA0.
            self.r.write(reg, (v & !EPCTL_STALL) | EPCTL_SD0PID);
            if k == 0 && self.out_st == OutSt::Armed {
                self.arm_out_regs();
            }
        }
    }

    fn set_configuration(&mut self, v: u8) {
        self.config = v;
        let (o, i) = (desc::EP_OUT as usize, desc::EP_IN as usize);
        if v == 0 {
            self.r.write(doepctl(o), EPCTL_SNAK);
            self.r.write(diepctl(i), EPCTL_SNAK);
            self.out_st = OutSt::Idle;
            self.in_busy = false;
            return;
        }
        let mps = self.bulk_mps();
        let txf = if self.hw.dedicated_fifos { 1 } else { 0 };
        self.r.write(doepctl(o), mps | EPCTL_USBACTEP | EPCTL_TYPE_BULK | EPCTL_SD0PID | EPCTL_SNAK);
        self.r.write(diepctl(i), mps | EPCTL_USBACTEP | EPCTL_TYPE_BULK | EPCTL_SD0PID | EPCTL_SNAK | (txf << EPCTL_TXFNUM_SHIFT));
        self.halted = [false; 2];
        self.in_busy = false;
        self.arm_out();
    }

    fn reply(&mut self, data: &[u8], wlength: usize) {
        let n = data.len().min(wlength).min(self.ctl.len());
        self.ctl[..n].copy_from_slice(&data[..n]);
        self.ctl_len = n;
        self.ctl_pos = 0;
        // A short answer that ends on a packet boundary needs a zero-length packet to end the data stage.
        self.ctl_zlp = n < wlength && n % desc::EP0_MPS as usize == 0 && n > 0;
        self.ep0 = Ep0::DataIn;
        self.start_ep0_packet();
    }

    fn start_ep0_packet(&mut self) {
        let n = (self.ctl_len - self.ctl_pos).min(desc::EP0_MPS as usize);
        self.r.write(dieptsiz(0), (1 << TSIZ_PKTCNT_SHIFT) | n as u32);
        let v = self.r.read(diepctl(0));
        self.r.write(diepctl(0), (v & !EPCTL_STALL) | EPCTL_EPENA | EPCTL_CNAK);
        self.ctl_pkt = Some(n);
        self.push_ep0();
    }

    fn status_in(&mut self) {
        self.ep0 = Ep0::StatusIn;
        self.r.write(dieptsiz(0), 1 << TSIZ_PKTCNT_SHIFT);
        let v = self.r.read(diepctl(0));
        self.r.write(diepctl(0), (v & !EPCTL_STALL) | EPCTL_EPENA | EPCTL_CNAK);
    }

    /// Unsupported request: STALL both directions of EP0 (the core clears it at the next SETUP).
    fn stall(&mut self) {
        self.stats.stalls += 1;
        self.ep0 = Ep0::Idle;
        let v = self.r.read(diepctl(0));
        self.r.write(diepctl(0), v | EPCTL_STALL);
        let v = self.r.read(doepctl(0));
        self.r.write(doepctl(0), v | EPCTL_STALL);
    }

    /// TX FIFO space in words for IN endpoint `ep`.
    fn tx_space(&mut self, ep: usize) -> u32 {
        if self.hw.dedicated_fifos {
            self.r.read(dtxfsts(ep)) & 0xFFFF
        } else {
            self.r.read(GNPTXSTS) & 0xFFFF
        }
    }

    fn push_ep0(&mut self) {
        let Some(n) = self.ctl_pkt else { return };
        // Shared FIFO: never interleave an EP0 packet with a half-pushed bulk packet.
        if !self.hw.dedicated_fifos && self.in_busy && self.in_pushed < self.in_len {
            return;
        }
        if self.tx_space(0) < n.div_ceil(4) as u32 {
            return;
        }
        let (a, b) = (self.ctl_pos, self.ctl_pos + n);
        let mut i = a;
        while i < b {
            let mut w = [0u8; 4];
            let k = (b - i).min(4);
            w[..k].copy_from_slice(&self.ctl[i..i + k]);
            self.r.write(fifo(0), u32::from_le_bytes(w));
            i += 4;
        }
        self.ctl_pos = b;
        self.ctl_pkt = None;
    }

    // ── bulk ─────────────────────────────────────────────────────────────────────────────────────

    fn arm_out(&mut self) {
        self.out_len = 0;
        self.out_st = OutSt::Armed;
        self.arm_out_regs();
    }

    fn arm_out_regs(&mut self) {
        let mps = self.bulk_mps() as usize;
        let pkts = (self.out_buf.len() / mps).clamp(1, 1023);
        let n = desc::EP_OUT as usize;
        self.r.write(doeptsiz(n), ((pkts as u32) << TSIZ_PKTCNT_SHIFT) | (pkts * mps) as u32);
        let v = self.r.read(doepctl(n));
        self.r.write(doepctl(n), (v & !EPCTL_SNAK) | EPCTL_EPENA | EPCTL_CNAK);
    }

    /// The completed bulk OUT transfer (one HQFL frame), if any. The endpoint NAKs until `rearm_out`.
    pub fn frame(&self) -> Option<&[u8]> {
        (self.out_st == OutSt::Done).then(|| &self.out_buf[..self.out_len])
    }

    /// Accept the next bulk OUT transfer.
    pub fn rearm_out(&mut self) {
        if self.config != 0 {
            self.arm_out();
        }
    }

    /// A bulk IN transfer is still in flight.
    pub fn in_busy(&self) -> bool {
        self.in_busy
    }

    /// Queue one response as one bulk IN transfer. `data.len()` must not be a multiple of the packet size (the
    /// transfer ends in a short packet, no ZLP). False if not configured, busy, or the frame does not fit.
    pub fn send(&mut self, data: &[u8]) -> bool {
        let mps = self.bulk_mps() as usize;
        if self.config == 0 || self.in_busy || data.is_empty() || data.len() > IN_BUF || data.len() % mps == 0 {
            return false;
        }
        self.in_buf[..data.len()].copy_from_slice(data);
        self.in_len = data.len();
        self.in_pushed = 0;
        self.in_busy = true;
        let n = desc::EP_IN as usize;
        let pkts = data.len().div_ceil(mps) as u32;
        self.r.write(dieptsiz(n), (pkts << TSIZ_PKTCNT_SHIFT) | data.len() as u32);
        let v = self.r.read(diepctl(n));
        self.r.write(diepctl(n), (v & !EPCTL_SNAK) | EPCTL_EPENA | EPCTL_CNAK);
        self.push_bulk();
        true
    }

    fn push_bulk(&mut self) {
        if !self.in_busy || self.in_pushed >= self.in_len {
            return;
        }
        if !self.hw.dedicated_fifos && self.ctl_pkt.is_some() {
            return;
        }
        let mps = self.bulk_mps() as usize;
        let ep = desc::EP_IN as usize;
        while self.in_pushed < self.in_len {
            let n = (self.in_len - self.in_pushed).min(mps);
            if self.tx_space(ep) < n.div_ceil(4) as u32 {
                return;
            }
            let (a, b) = (self.in_pushed, self.in_pushed + n);
            let mut i = a;
            while i < b {
                let mut w = [0u8; 4];
                let k = (b - i).min(4);
                w[..k].copy_from_slice(&self.in_buf[i..i + k]);
                self.r.write(fifo(ep), u32::from_le_bytes(w));
                i += 4;
            }
            self.in_pushed = b;
        }
    }
}

fn wait<R: Regs>(r: &mut R, reg: usize, bit: u32, set: bool) -> Result<(), InitErr> {
    for _ in 0..100_000 {
        let v = r.read(reg);
        if (v & bit != 0) == set {
            return Ok(());
        }
        r.delay_us(1);
    }
    Err(InitErr::ResetTimeout(r.read(reg)))
}

fn flush<R: Regs>(r: &mut R, what: u32) -> Result<(), InitErr> {
    r.write(GRSTCTL, what);
    let bit = what & (GRSTCTL_TXFFLSH | GRSTCTL_RXFFLSH);
    wait(r, GRSTCTL, bit, false)?;
    r.delay_us(1);
    Ok(())
}
