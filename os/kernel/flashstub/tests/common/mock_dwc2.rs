// SPDX-License-Identifier: AGPL-3.0-only
//! A register-level model of a DWC2 core in device mode, plus the USB host on the other side of it. The driver
//! under test (`flashstub::dwc2`) talks to `MockRegs` exactly as it talks to the MMIO window; the tests play the
//! host with `Host` (SETUP / IN / OUT tokens, NAK, STALL, short packets).
//!
//! Modelled: GSNPSID / GHWCFG identity, the core soft reset (both the self-clearing CSRST of older cores and the
//! CSRST_DONE handshake of 4.20a+), FIFO flushes, the shared RX FIFO with its GRXSTSP status words and capacity,
//! per-endpoint TX FIFOs (dedicated) or one shared non-periodic TX FIFO with DTXFSTS / GNPTXSTS free space, packet
//! and byte counts in DxEPTSIZ, EPENA / NAK / STALL / EPDIS, write-1-to-clear interrupt bits, DAINT and the
//! GINTSTS summary bits, the device address the host must use after SET_ADDRESS. The model panics on driver
//! behaviour real hardware would mishandle (a FIFO push to a disabled endpoint, a token to the wrong address).
//! Not modelled: data toggles, timing, DMA, interrupts (the driver polls).
use flashstub::dwc2::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

pub const DWC2_ID: u32 = 0x4F54_330A;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PopAction {
    None,
    Setup,
    OutDone(usize),
}

struct RxEntry {
    status: u32,
    data: Vec<u8>,
    on_pop: PopAction,
}

pub struct Model {
    pub regs: std::collections::HashMap<usize, u32>,
    pub snpsid: u32,
    pub hwcfg: [u32; 4],
    pub csrst_done_style: bool,
    pub high_speed: bool,
    pub soft_resets: u32,
    rx: VecDeque<RxEntry>,
    cur: VecDeque<u32>,
    /// per IN endpoint: the packet being assembled from FIFO pushes, and completed packets
    asm: [Vec<u8>; 16],
    txq: [VecDeque<Vec<u8>>; 16],
    enum_pending: bool,
    pub fifo_pushes: u64,
    /// register writes by the driver (a refused core must see none)
    pub writes: u64,
    /// the address the core answers to: DCFG.DAD takes effect when the SET_ADDRESS status stage completes
    addr_eff: u8,
}

impl Model {
    pub fn new(snpsid: u32, dedicated: bool) -> Model {
        let hwcfg2 = (1 << 6) | (2 << 3) | (5 << 10); // UTMI+ HS PHY, internal DMA arch, 5 device endpoints
        let hwcfg3 = 0x0FF0 << 16; // 4080 words of FIFO RAM
        let hwcfg4 = if dedicated { (1 << 25) | (5 << 26) } else { 0 };
        let mut regs = std::collections::HashMap::new();
        regs.insert(GUSBCFG, 0x0000_1407 | GUSBCFG_FHMOD); // firmware left: 8-bit UTMI+, host mode forced
        regs.insert(DCTL, 0);
        Model {
            regs,
            snpsid,
            hwcfg: [0, hwcfg2, hwcfg3, hwcfg4],
            csrst_done_style: false,
            high_speed: true,
            soft_resets: 0,
            rx: VecDeque::new(),
            cur: VecDeque::new(),
            asm: Default::default(),
            txq: Default::default(),
            enum_pending: false,
            fifo_pushes: 0,
            writes: 0,
            addr_eff: 0,
        }
    }

    fn get(&self, off: usize) -> u32 {
        *self.regs.get(&off).unwrap_or(&0)
    }
    fn set(&mut self, off: usize, v: u32) {
        self.regs.insert(off, v);
    }
    fn dedicated(&self) -> bool {
        self.hwcfg[3] & (1 << 25) != 0
    }

    fn rx_words_used(&self) -> usize {
        self.rx.iter().map(|e| 1 + e.data.len().div_ceil(4)).sum::<usize>() + self.cur.len()
    }

    fn in_mps(&self, ep: usize) -> usize {
        let c = self.get(diepctl(ep));
        if ep == 0 {
            [64, 32, 16, 8][(c & 3) as usize]
        } else {
            (c & EPCTL_MPS_MASK) as usize
        }
    }
    fn out_mps(&self, ep: usize) -> usize {
        if ep == 0 {
            64
        } else {
            (self.get(doepctl(ep)) & EPCTL_MPS_MASK) as usize
        }
    }

    fn tx_fifo_of(&self, ep: usize) -> usize {
        if !self.dedicated() || ep == 0 {
            0
        } else {
            ((self.get(diepctl(ep)) >> EPCTL_TXFNUM_SHIFT) & 0xF) as usize
        }
    }
    fn tx_depth(&self, fifo: usize) -> usize {
        if fifo == 0 {
            (self.get(GNPTXFSIZ) >> 16) as usize
        } else {
            (self.get(DIEPTXF1 + 4 * (fifo - 1)) >> 16) as usize
        }
    }
    fn tx_used(&self, fifo: usize) -> usize {
        (0..16)
            .filter(|&ep| self.tx_fifo_of(ep) == fifo)
            .map(|ep| self.asm[ep].len().div_ceil(4) + self.txq[ep].iter().map(|p| p.len().div_ceil(4)).sum::<usize>())
            .sum()
    }

    fn daint(&self) -> u32 {
        let mut d = 0;
        for ep in 0..16 {
            if self.get(diepint(ep)) != 0 {
                d |= 1 << ep;
            }
            if self.get(doepint(ep)) != 0 {
                d |= 1 << (16 + ep);
            }
        }
        d
    }

    fn soft_reset(&mut self) {
        self.soft_resets += 1;
        let keep = [GUSBCFG, GRXFSIZ, GNPTXFSIZ, DIEPTXF1, DIEPTXF1 + 4];
        let saved: Vec<(usize, u32)> = keep.iter().map(|&k| (k, self.get(k))).collect();
        self.regs.clear();
        for (k, v) in saved {
            self.set(k, v);
        }
        // the soft disconnect does not survive the reset: the driver must assert it again
        self.set(DCTL, 0);
        self.rx.clear();
        self.cur.clear();
        self.asm = Default::default();
        self.txq = Default::default();
    }

    pub fn read(&mut self, off: usize) -> u32 {
        match off {
            GSNPSID => self.snpsid,
            GHWCFG1 => self.hwcfg[0],
            GHWCFG2 => self.hwcfg[1],
            GHWCFG3 => self.hwcfg[2],
            GHWCFG4 => self.hwcfg[3],
            GRSTCTL => self.get(GRSTCTL) | GRSTCTL_AHBIDL,
            GINTSTS => {
                let mut v = self.get(GINTSTS);
                if !self.rx.is_empty() {
                    v |= GINTSTS_RXFLVL;
                }
                let d = self.daint();
                if d & 0xFFFF != 0 {
                    v |= GINTSTS_IEPINT;
                }
                if d >> 16 != 0 {
                    v |= GINTSTS_OEPINT;
                }
                v
            }
            DAINT => self.daint(),
            DSTS => {
                if self.high_speed {
                    0
                } else {
                    1 << 1
                }
            }
            GRXSTSP => {
                assert!(self.cur.is_empty(), "GRXSTSP popped before the previous packet's data was read");
                let e = self.rx.pop_front().expect("GRXSTSP read with an empty RX FIFO");
                for c in e.data.chunks(4) {
                    let mut w = [0u8; 4];
                    w[..c.len()].copy_from_slice(c);
                    self.cur.push_back(u32::from_le_bytes(w));
                }
                match e.on_pop {
                    PopAction::Setup => {
                        let v = self.get(doepint(0));
                        self.set(doepint(0), v | DOEPINT_SETUP);
                    }
                    PopAction::OutDone(ep) => {
                        let v = self.get(doepint(ep));
                        self.set(doepint(ep), v | EPINT_XFERCOMPL);
                        let c = self.get(doepctl(ep));
                        self.set(doepctl(ep), (c & !EPCTL_EPENA) | EPCTL_NAKSTS);
                    }
                    PopAction::None => {}
                }
                e.status
            }
            o if (0x1000..0x11000).contains(&o) => self.cur.pop_front().expect("RX FIFO read past the popped packet"),
            o if o >= 0x918 && o < 0xB00 && (o - 0x918) % 0x20 == 0 => {
                let ep = (o - 0x918) / 0x20;
                let f = self.tx_fifo_of(ep);
                (self.tx_depth(f) - self.tx_used(f)) as u32
            }
            GNPTXSTS => {
                assert!(!self.dedicated(), "GNPTXSTS used with dedicated FIFOs");
                (self.tx_depth(0) - self.tx_used(0)) as u32
            }
            _ => self.get(off),
        }
    }

    pub fn write(&mut self, off: usize, v: u32) {
        self.writes += 1;
        match off {
            GINTSTS => {
                let cur = self.get(GINTSTS);
                self.set(GINTSTS, cur & !v);
                if v & GINTSTS_USBRST != 0 && self.enum_pending {
                    self.enum_pending = false;
                    let s = self.get(GINTSTS);
                    self.set(GINTSTS, s | GINTSTS_ENUMDNE);
                }
            }
            GRSTCTL => {
                if v & GRSTCTL_CSRST != 0 {
                    self.soft_reset();
                    self.set(GRSTCTL, if self.csrst_done_style { GRSTCTL_CSRST | GRSTCTL_CSRST_DONE } else { 0 });
                    return;
                }
                if v & GRSTCTL_CSRST_DONE != 0 {
                    self.set(GRSTCTL, 0); // 4.20a+ acknowledge
                    return;
                }
                if v & GRSTCTL_TXFFLSH != 0 {
                    let n = ((v >> 6) & 0x1F) as usize;
                    for ep in 0..16 {
                        if n == 0x10 || self.tx_fifo_of(ep) == n {
                            self.asm[ep].clear();
                            self.txq[ep].clear();
                        }
                    }
                }
                if v & GRSTCTL_RXFFLSH != 0 {
                    self.rx.clear();
                    self.cur.clear();
                }
                self.set(GRSTCTL, 0);
            }
            o if (o >= 0x908 && o < 0xB00 && (o - 0x908) % 0x20 == 0) || (o >= 0xB08 && o < 0xD00 && (o - 0xB08) % 0x20 == 0) => {
                let c = self.get(o);
                self.set(o, c & !v); // write 1 to clear
            }
            o if (o >= 0x900 && o < 0xB00 && (o - 0x900) % 0x20 == 0) || (o >= 0xB00 && o < 0xD00 && (o - 0xB00) % 0x20 == 0) => {
                let mut c = (self.get(o) & (EPCTL_NAKSTS | EPCTL_EPENA)) | (v & !(EPCTL_CNAK | EPCTL_SNAK | EPCTL_SD0PID | EPCTL_EPDIS | EPCTL_NAKSTS));
                if v & EPCTL_EPENA == 0 && self.get(o) & EPCTL_EPENA != 0 && v & EPCTL_EPDIS == 0 {
                    c |= EPCTL_EPENA; // EPENA is cleared only by the core or by EPDIS
                }
                if v & EPCTL_CNAK != 0 {
                    c &= !EPCTL_NAKSTS;
                }
                if v & EPCTL_SNAK != 0 {
                    c |= EPCTL_NAKSTS;
                }
                if v & EPCTL_EPDIS != 0 {
                    c &= !EPCTL_EPENA;
                    let int = o + 8;
                    let i = self.get(int);
                    self.set(int, i | EPINT_EPDISBLD);
                }
                self.set(o, c);
            }
            o if (0x1000..0x11000).contains(&o) => {
                let ep = o / 0x1000 - 1;
                let ctl = self.get(diepctl(ep));
                assert!(ctl & EPCTL_EPENA != 0, "TX FIFO push to IN endpoint {ep} while it is disabled");
                let tsiz = self.get(dieptsiz(ep));
                let xfer = (tsiz & if ep == 0 { 0x7F } else { 0x7FFFF }) as usize;
                let queued: usize = self.txq[ep].iter().map(|p| p.len()).sum();
                let pkt = (xfer - queued).min(self.in_mps(ep));
                assert!(pkt > 0, "TX FIFO push to endpoint {ep} beyond its programmed transfer size");
                let f = self.tx_fifo_of(ep);
                assert!(self.tx_used(f) < self.tx_depth(f), "TX FIFO {f} overflow (push without checking free space)");
                self.asm[ep].extend_from_slice(&v.to_le_bytes());
                self.fifo_pushes += 1;
                if self.asm[ep].len() >= pkt {
                    let mut p = std::mem::take(&mut self.asm[ep]);
                    p.truncate(pkt);
                    self.txq[ep].push_back(p);
                }
            }
            _ => self.set(off, v),
        }
    }

    // ── the host side ───────────────────────────────────────────────────────────────────────────

    pub fn connected(&self) -> bool {
        self.get(DCTL) & DCTL_SFTDISCON == 0
    }
    pub fn address(&self) -> u8 {
        self.addr_eff
    }
    fn dcfg_addr(&self) -> u8 {
        ((self.get(DCFG) & DCFG_DAD_MASK) >> DCFG_DAD_SHIFT) as u8
    }

    pub fn bus_reset(&mut self) {
        assert!(self.connected(), "bus reset while the device is soft-disconnected");
        let s = self.get(GINTSTS);
        self.set(GINTSTS, s | GINTSTS_USBRST);
        self.enum_pending = true;
        self.addr_eff = 0;
    }

    pub fn setup(&mut self, addr: u8, pkt: [u8; 8]) {
        assert_eq!(self.address(), addr, "SETUP to address {addr}, device has {}", self.address());
        for o in [diepctl(0), doepctl(0)] {
            let c = self.get(o);
            self.set(o, c & !EPCTL_STALL); // a SETUP clears an EP0 stall
        }
        self.rx.push_back(RxEntry { status: (8 << 4) | (PKT_SETUP_DATA << 17), data: pkt.to_vec(), on_pop: PopAction::None });
        self.rx.push_back(RxEntry { status: PKT_SETUP_DONE << 17, data: vec![], on_pop: PopAction::Setup });
    }

    pub fn in_token(&mut self, addr: u8, ep: usize) -> Tok {
        assert_eq!(self.address(), addr, "IN to address {addr}, device has {}", self.address());
        let ctl = self.get(diepctl(ep));
        if ctl & EPCTL_STALL != 0 {
            return Tok::Stall;
        }
        if ctl & EPCTL_EPENA == 0 || ctl & EPCTL_NAKSTS != 0 {
            return Tok::Nak;
        }
        let tsiz = self.get(dieptsiz(ep));
        let (pmask, xmask) = if ep == 0 { (0x3, 0x7F) } else { (0x3FF, 0x7FFFF) };
        let pktcnt = (tsiz >> 19) & pmask;
        let xfer = tsiz & xmask;
        let pkt = if let Some(p) = self.txq[ep].pop_front() {
            p
        } else if xfer == 0 && pktcnt > 0 {
            vec![] // a zero-length packet needs no FIFO data
        } else {
            return Tok::Nak; // data not pushed yet
        };
        let (pktcnt, xfer) = (pktcnt - 1, xfer - pkt.len() as u32);
        self.set(dieptsiz(ep), (tsiz & !((pmask << 19) | xmask)) | (pktcnt << 19) | xfer);
        if ep == 0 && pkt.is_empty() {
            self.addr_eff = self.dcfg_addr(); // a status stage completed: a new address now applies
        }
        if pktcnt == 0 {
            self.set(diepctl(ep), ctl & !EPCTL_EPENA);
            let i = self.get(diepint(ep));
            self.set(diepint(ep), i | EPINT_XFERCOMPL);
        }
        Tok::Data(pkt)
    }

    pub fn out_token(&mut self, addr: u8, ep: usize, data: &[u8]) -> Tok {
        assert_eq!(self.address(), addr, "OUT to address {addr}, device has {}", self.address());
        assert!(data.len() <= self.out_mps(ep).max(64), "OUT packet larger than max packet");
        let ctl = self.get(doepctl(ep));
        if ctl & EPCTL_STALL != 0 {
            return Tok::Stall;
        }
        if ctl & EPCTL_EPENA == 0 || ctl & EPCTL_NAKSTS != 0 {
            return Tok::Nak;
        }
        let cap = self.get(GRXFSIZ) as usize;
        if self.rx_words_used() + 2 + data.len().div_ceil(4) > cap {
            return Tok::Nak; // RX FIFO full: the driver has not drained it
        }
        let tsiz = self.get(doeptsiz(ep));
        let (pmask, xmask) = if ep == 0 { (0x1, 0x7F) } else { (0x3FF, 0x7FFFF) };
        let pktcnt = ((tsiz >> 19) & pmask).saturating_sub(1);
        let xfer = (tsiz & xmask).saturating_sub(data.len() as u32);
        self.set(doeptsiz(ep), (tsiz & !((pmask << 19) | xmask)) | (pktcnt << 19) | xfer);
        self.rx.push_back(RxEntry { status: ep as u32 | ((data.len() as u32) << 4) | (PKT_OUT_DATA << 17), data: data.to_vec(), on_pop: PopAction::None });
        if data.len() < self.out_mps(ep) || pktcnt == 0 || xfer == 0 {
            // transfer complete: the core NAKs further OUT tokens until the driver re-enables the endpoint
            let c = self.get(doepctl(ep));
            self.set(doepctl(ep), c | EPCTL_NAKSTS);
            self.rx.push_back(RxEntry { status: ep as u32 | (PKT_OUT_DONE << 17), data: vec![], on_pop: PopAction::OutDone(ep) });
        }
        Tok::Ack
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Tok {
    Ack,
    Nak,
    Stall,
    Data(Vec<u8>),
}

/// The driver's view: the MMIO window.
#[derive(Clone)]
pub struct MockRegs(pub Rc<RefCell<Model>>);
impl Regs for MockRegs {
    fn read(&mut self, off: usize) -> u32 {
        self.0.borrow_mut().read(off)
    }
    fn write(&mut self, off: usize, val: u32) {
        self.0.borrow_mut().write(off, val)
    }
    fn delay_us(&mut self, _us: u32) {}
}

#[derive(Debug, PartialEq, Eq)]
pub struct Stalled;

/// The USB host: tokens with NAK retries, the device loop run between them.
pub struct Host {
    pub m: Rc<RefCell<Model>>,
    pub addr: u8,
}

const PATIENCE: usize = 20_000;

impl Host {
    fn retry(&mut self, pump: &mut dyn FnMut(), mut tok: impl FnMut(&mut Model) -> Tok) -> Tok {
        for _ in 0..PATIENCE {
            pump();
            let t = tok(&mut self.m.borrow_mut());
            if t != Tok::Nak {
                return t;
            }
        }
        panic!("the device NAKed {PATIENCE} times");
    }

    pub fn reset(&mut self, pump: &mut dyn FnMut()) {
        self.m.borrow_mut().bus_reset();
        self.addr = 0;
        for _ in 0..4 {
            pump();
        }
    }

    pub fn control_in(&mut self, pump: &mut dyn FnMut(), setup: [u8; 8]) -> Result<Vec<u8>, Stalled> {
        let wlen = u16::from_le_bytes([setup[6], setup[7]]) as usize;
        let a = self.addr;
        self.m.borrow_mut().setup(a, setup);
        let mut data = vec![];
        loop {
            match self.retry(pump, |m| m.in_token(a, 0)) {
                Tok::Stall => return Err(Stalled),
                Tok::Data(p) => {
                    let short = p.len() < 64;
                    data.extend(p);
                    if short || data.len() >= wlen {
                        break;
                    }
                }
                t => panic!("unexpected {t:?}"),
            }
        }
        match self.retry(pump, |m| m.out_token(a, 0, &[])) {
            Tok::Ack => {}
            t => panic!("status stage: {t:?}"),
        }
        for _ in 0..4 {
            pump();
        }
        Ok(data)
    }

    pub fn control_nodata(&mut self, pump: &mut dyn FnMut(), setup: [u8; 8]) -> Result<(), Stalled> {
        let a = self.addr;
        self.m.borrow_mut().setup(a, setup);
        match self.retry(pump, |m| m.in_token(a, 0)) {
            Tok::Stall => Err(Stalled),
            Tok::Data(p) if p.is_empty() => {
                for _ in 0..4 {
                    pump();
                }
                Ok(())
            }
            t => panic!("status stage: {t:?}"),
        }
    }

    pub fn set_address(&mut self, pump: &mut dyn FnMut(), addr: u8) {
        self.control_nodata(pump, [0x00, 0x05, addr, 0, 0, 0, 0, 0]).expect("SET_ADDRESS");
        self.addr = addr; // the new address applies after the status stage
    }

    pub fn bulk_out(&mut self, pump: &mut dyn FnMut(), ep: usize, data: &[u8]) -> Result<(), Stalled> {
        assert_ne!(data.len() % 512, 0, "an HQFL frame is never a multiple of 512");
        let a = self.addr;
        for c in data.chunks(512) {
            match self.retry(pump, |m| m.out_token(a, ep, c)) {
                Tok::Ack => {}
                Tok::Stall => return Err(Stalled),
                t => panic!("{t:?}"),
            }
        }
        Ok(())
    }

    pub fn bulk_in(&mut self, pump: &mut dyn FnMut(), ep: usize) -> Result<Vec<u8>, Stalled> {
        let a = self.addr;
        let mut v = vec![];
        loop {
            match self.retry(pump, |m| m.in_token(a, ep)) {
                Tok::Data(p) => {
                    let short = p.len() < 512;
                    v.extend(p);
                    if short {
                        return Ok(v);
                    }
                }
                Tok::Stall => return Err(Stalled),
                t => panic!("{t:?}"),
            }
        }
    }
}

pub fn setup_pkt(bm: u8, req: u8, value: u16, index: u16, len: u16) -> [u8; 8] {
    let (v, i, l) = (value.to_le_bytes(), index.to_le_bytes(), len.to_le_bytes());
    [bm, req, v[0], v[1], i[0], i[1], l[0], l[1]]
}
