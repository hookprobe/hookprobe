//! ADR 0065 step 4b-1: the SDHCI / SDIO bus primitives of the CYW43455 driver, generic over register access.
//!
//! Lifted unchanged from `arch-aarch64::cyw43` (command issue with the inhibit-recovery reset, CMD52, CMD53
//! byte + block transfers by PIO, the F1 backplane window, 32-bit backplane access) so the SAME code runs in the
//! kernel driver (over its SDHCI mapping) and in `el0-wifi` (over its Device grant, steps 4b-4e). No statics: the
//! diagnostics the driver prints live in the `Bus` value.

/// Byte / halfword / word access to the SDHCI register page (offsets from its base).
pub trait Mmio {
    fn r8(&self, o: usize) -> u8;
    fn r16(&self, o: usize) -> u16;
    fn r32(&self, o: usize) -> u32;
    fn w8(&self, o: usize, v: u8);
    fn w16(&self, o: usize, v: u16);
    fn w32(&self, o: usize, v: u32);
}

// --- SDHCI registers (SD Host Controller v3) ---
pub const BLK_SIZE_CNT: usize = 0x04;
pub const ARG1: usize = 0x08;
pub const CMD_XFER: usize = 0x0C;
pub const RESP0: usize = 0x10;
pub const BUF_DATA: usize = 0x20;
pub const PRESENT_STATE: usize = 0x24;
pub const INT_STATUS: usize = 0x30;
pub const CMD_INHIBIT: u32 = 1 << 0;
pub const DAT_INHIBIT: u32 = 1 << 1;
pub const RST_CMD: u8 = 1 << 1;
pub const RST_DAT: u8 = 1 << 2;
pub const INT_CMD_DONE: u32 = 1 << 0;
pub const INT_XFER_DONE: u32 = 1 << 1;
pub const INT_BUF_WR_RDY: u32 = 1 << 4;
pub const INT_BUF_RD_RDY: u32 = 1 << 5;
pub const INT_ERR: u32 = 1 << 15;
pub const RESP_48: u16 = 0b10;
pub const CMD_CRC_CHK: u16 = 1 << 3;
pub const CMD_IDX_CHK: u16 = 1 << 4;
pub const CMD_DATA: u16 = 1 << 5;
pub const XM_READ: u16 = 1 << 4;
pub const XM_BLKCNT_EN: u16 = 1 << 1;
pub const XM_MULTI: u16 = 1 << 5;
pub const CMD52_IO_RW_DIRECT: u16 = 52;
pub const CMD53_IO_RW_EXTENDED: u16 = 53;
// F1 backplane window registers
pub const SB_ADDR_LOW: u32 = 0x1000A;
pub const SB_ADDR_MID: u32 = 0x1000B;
pub const SB_ADDR_HIGH: u32 = 0x1000C;

pub struct Bus<M: Mmio> {
    pub m: M,
    /// Wi-Fi degraded (wifiheal): every access fails at once, the bus is never touched.
    pub off: bool,
    /// (present state, int status) of the last failed command.
    pub sdio_diag: (u32, u32),
    /// (stage, int status, present state) of the last failed byte / F1-block write.
    pub cmd53_diag: (u8, u32, u32),
    /// (stage << 24 | int status) of the last failed 512-B block transfer.
    pub blk_diag: u32,
}

impl<M: Mmio> Bus<M> {
    pub const fn new(m: M) -> Self {
        Bus { m, off: false, sdio_diag: (0, 0), cmd53_diag: (0, 0, 0), blk_diag: 0 }
    }

    /// Issue one command; Some(RESP0) when it completed without an error.
    pub fn cmd(&mut self, idx: u16, arg: u32, resp_kind: u16, crc_idx: bool, data: bool) -> Option<u32> {
        if self.off {
            return None;
        }
        let m = &self.m;
        let mut spin = 0u32;
        let inhibit = CMD_INHIBIT | if data { DAT_INHIBIT } else { 0 };
        while m.r32(PRESENT_STATE) & inhibit != 0 {
            spin += 1;
            if spin > 200_000 {
                // Inhibit stuck (the command engine wedged on an in-band card interrupt): soft-reset the CMD (+ DAT
                // for data commands) circuit, then proceed. Standard SDHCI error recovery.
                let mut rb = RST_CMD;
                if data {
                    rb |= RST_DAT;
                }
                m.w8(0x2F, rb);
                let mut rs = 0u32;
                while m.r8(0x2F) & rb != 0 && rs < 200_000 {
                    rs += 1;
                }
                break;
            }
        }
        m.w32(INT_STATUS, 0xFFFF_FFFF); // clear stale
        m.w32(ARG1, arg);
        let mut flags = resp_kind;
        if crc_idx && resp_kind != 0 {
            flags |= CMD_CRC_CHK | CMD_IDX_CHK;
        }
        if data {
            flags |= CMD_DATA;
        }
        m.w16(CMD_XFER + 2, (idx << 8) | flags);
        let mut spin = 0u32;
        loop {
            let st = m.r32(INT_STATUS);
            if st & INT_ERR != 0 {
                self.sdio_diag = (m.r32(PRESENT_STATE), st);
                return None;
            }
            if st & INT_CMD_DONE != 0 {
                break;
            }
            spin += 1;
            if spin > 1_000_000 {
                self.sdio_diag = (m.r32(PRESENT_STATE), st);
                return None;
            }
        }
        Some(m.r32(RESP0))
    }

    /// CMD52 (IO_RW_DIRECT): one byte on function `fnum`; returns the read / echoed byte.
    pub fn cmd52(&mut self, write: bool, fnum: u32, addr: u32, val: u8) -> Option<u8> {
        let arg = ((write as u32) << 31) | ((fnum & 7) << 28) | ((write as u32) << 27) | ((addr & 0x1_FFFF) << 9) | (val as u32);
        self.cmd(CMD52_IO_RW_DIRECT, arg, RESP_48, true, false).map(|r| (r & 0xFF) as u8)
    }

    fn wait(&self, bit: u32, limit: u32) -> Result<(), u32> {
        let mut spin = 0u32;
        loop {
            let st = self.m.r32(INT_STATUS);
            if st & bit != 0 {
                return Ok(());
            }
            if st & INT_ERR != 0 {
                return Err(st);
            }
            spin += 1;
            if spin > limit {
                return Err(st);
            }
        }
    }

    /// CMD53 byte-mode read (<= 512 B). F2 (the WLAN FIFO) is read at a FIXED address, F1 incrementing (brcmfmac).
    pub fn cmd53_read(&mut self, fnum: u32, addr: u32, out: &mut [u8]) -> bool {
        let n = out.len().min(512);
        self.m.w16(BLK_SIZE_CNT, n as u16);
        self.m.w16(BLK_SIZE_CNT + 2, 1);
        self.m.w16(CMD_XFER, XM_READ | XM_BLKCNT_EN);
        let incr: u32 = if fnum == 2 { 0 } else { 1 };
        let arg = ((fnum & 7) << 28) | (incr << 26) | ((addr & 0x1_FFFF) << 9) | (n as u32 & 0x1FF);
        if self.cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
            return false;
        }
        if self.wait(INT_BUF_RD_RDY, 1_000_000).is_err() {
            return false;
        }
        let mut i = 0;
        while i < n {
            let word = self.m.r32(BUF_DATA);
            for b in 0..4 {
                if i < n {
                    out[i] = ((word >> (b * 8)) & 0xFF) as u8;
                    i += 1;
                }
            }
        }
        self.wait(INT_XFER_DONE, 1_000_000).is_ok()
    }

    /// CMD53 byte-mode write (<= 512 B, incrementing).
    pub fn cmd53_write(&mut self, fnum: u32, addr: u32, data: &[u8]) -> bool {
        let n = data.len().min(512);
        self.m.w16(BLK_SIZE_CNT, n as u16);
        self.m.w16(BLK_SIZE_CNT + 2, 1);
        self.m.w16(CMD_XFER, XM_BLKCNT_EN);
        let arg = (1 << 31) | ((fnum & 7) << 28) | (1 << 26) | ((addr & 0x1_FFFF) << 9) | (n as u32 & 0x1FF);
        if self.cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
            self.cmd53_diag = (1, self.m.r32(INT_STATUS), self.m.r32(PRESENT_STATE));
            return false;
        }
        if let Err(st) = self.wait(INT_BUF_WR_RDY, 1_000_000) {
            self.cmd53_diag = (if st & INT_ERR != 0 { 2 } else { 3 }, st, self.m.r32(PRESENT_STATE));
            return false;
        }
        let mut i = 0;
        while i < n {
            let mut word = 0u32;
            for b in 0..4 {
                if i < n {
                    word |= (data[i] as u32) << (b * 8);
                    i += 1;
                }
            }
            self.m.w32(BUF_DATA, word);
        }
        if let Err(st) = self.wait(INT_XFER_DONE, 2_000_000) {
            self.cmd53_diag = (if st & INT_ERR != 0 { 4 } else { 5 }, st, self.m.r32(PRESENT_STATE));
            return false;
        }
        true
    }

    /// CMD53 BLOCK-mode read of `nblocks` x `bs` bytes (F2: FIXED address, as Linux on this CM5).
    pub fn cmd53_read_blocks(&mut self, fnum: u32, addr: u32, out: &mut [u8], nblocks: u32, bs: usize) -> bool {
        let need = (nblocks as usize) * bs;
        if out.len() < need || nblocks == 0 || nblocks > 0x1ff || !bs.is_multiple_of(4) {
            return false;
        }
        self.m.w16(BLK_SIZE_CNT, bs as u16);
        self.m.w16(BLK_SIZE_CNT + 2, nblocks as u16);
        self.m.w16(CMD_XFER, XM_READ | XM_BLKCNT_EN | XM_MULTI);
        let incr: u32 = if fnum == 2 { 0 } else { 1 };
        let arg = ((fnum & 7) << 28) | (1 << 27) | (incr << 26) | ((addr & 0x1_FFFF) << 9) | (nblocks & 0x1FF);
        if self.cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
            self.blk_diag = (1 << 24) | (self.m.r32(INT_STATUS) & 0xff_ffff);
            return false;
        }
        let mut i = 0usize;
        for _ in 0..nblocks {
            if let Err(st) = self.wait(INT_BUF_RD_RDY, 1_000_000) {
                self.blk_diag = ((if st & INT_ERR != 0 { 2 } else { 3 }) << 24) | (st & 0xff_ffff);
                return false;
            }
            self.m.w32(INT_STATUS, INT_BUF_RD_RDY); // W1C so the next block waits fresh
            for _ in 0..(bs / 4) {
                out[i..i + 4].copy_from_slice(&self.m.r32(BUF_DATA).to_le_bytes());
                i += 4;
            }
        }
        if let Err(st) = self.wait(INT_XFER_DONE, 4_000_000) {
            self.blk_diag = ((if st & INT_ERR != 0 { 4 } else { 5 }) << 24) | (st & 0xff_ffff);
            return false;
        }
        true
    }

    /// CMD53 BLOCK-mode write of `nblocks` x `bs` bytes, incrementing.
    pub fn cmd53_write_blocks(&mut self, fnum: u32, addr: u32, data: &[u8], nblocks: u32, bs: usize) -> bool {
        let need = (nblocks as usize) * bs;
        if data.len() < need || nblocks == 0 || nblocks > 0x1ff || !bs.is_multiple_of(4) {
            return false;
        }
        self.m.w16(BLK_SIZE_CNT, bs as u16);
        self.m.w16(BLK_SIZE_CNT + 2, nblocks as u16);
        self.m.w16(CMD_XFER, XM_BLKCNT_EN | XM_MULTI);
        let arg = (1 << 31) | ((fnum & 7) << 28) | (1 << 27) | (1 << 26) | ((addr & 0x1_FFFF) << 9) | (nblocks & 0x1FF);
        if self.cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
            self.cmd53_diag = (1, self.m.r32(INT_STATUS), self.m.r32(PRESENT_STATE));
            return false;
        }
        let mut i = 0usize;
        for _ in 0..nblocks {
            if let Err(st) = self.wait(INT_BUF_WR_RDY, 1_000_000) {
                self.cmd53_diag = (if st & INT_ERR != 0 { 2 } else { 3 }, st, self.m.r32(PRESENT_STATE));
                return false;
            }
            self.m.w32(INT_STATUS, INT_BUF_WR_RDY); // W1C so the next block waits fresh
            for _ in 0..(bs / 4) {
                self.m.w32(BUF_DATA, u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]));
                i += 4;
            }
        }
        if let Err(st) = self.wait(INT_XFER_DONE, 4_000_000) {
            self.cmd53_diag = (if st & INT_ERR != 0 { 4 } else { 5 }, st, self.m.r32(PRESENT_STATE));
            return false;
        }
        true
    }

    /// Point the F1 window at `addr` (bits [31:8]; the window is 0x8000-aligned, brcmfmac's masking).
    pub fn set_backplane_window(&mut self, addr: u32) -> bool {
        let a = self.cmd52(true, 1, SB_ADDR_LOW, ((addr >> 8) & 0xFF) as u8);
        let b = self.cmd52(true, 1, SB_ADDR_MID, ((addr >> 16) & 0xFF) as u8);
        let c = self.cmd52(true, 1, SB_ADDR_HIGH, ((addr >> 24) & 0xFF) as u8);
        a.is_some() && b.is_some() && c.is_some()
    }

    /// A 32-bit backplane read (4 CMD52 bytes through the window; 0xFF per failed byte).
    pub fn bp_r32(&mut self, addr: u32) -> u32 {
        self.set_backplane_window(addr);
        let base = addr & 0x7FFF;
        let mut b = [0u8; 4];
        for (i, x) in b.iter_mut().enumerate() {
            *x = self.cmd52(false, 1, base + i as u32, 0).unwrap_or(0xFF);
        }
        u32::from_le_bytes(b)
    }

    /// A 32-bit ATOMIC backplane write (one CMD53, 4-byte access flag 0x8000: the AI wrapper control registers
    /// take only a single 32-bit access).
    pub fn bp_w32(&mut self, addr: u32, val: u32) -> bool {
        self.set_backplane_window(addr);
        self.cmd53_write(1, (addr & 0x7FFF) | 0x8000, &val.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    extern crate std;
    use std::vec::Vec;

    /// A fake SDHCI: commands complete at once, RESP0 echoes CMD52's argument byte, the data port reads a counter
    /// and records writes; `fail` makes the next command raise INT_ERR.
    struct Fake {
        regs: RefCell<[u32; 64]>,
        writes: RefCell<Vec<(usize, u32)>>,
        data_out: RefCell<Vec<u32>>,
        ctr: RefCell<u32>,
        fail: RefCell<bool>,
    }
    impl Fake {
        fn new() -> Self {
            Fake { regs: RefCell::new([0; 64]), writes: RefCell::new(Vec::new()), data_out: RefCell::new(Vec::new()), ctr: RefCell::new(0), fail: RefCell::new(false) }
        }
    }
    impl Mmio for Fake {
        fn r8(&self, o: usize) -> u8 {
            (self.r32(o & !3) >> ((o & 3) * 8)) as u8
        }
        fn r16(&self, o: usize) -> u16 {
            (self.r32(o & !3) >> ((o & 3) * 8)) as u16
        }
        fn r32(&self, o: usize) -> u32 {
            match o {
                INT_STATUS => {
                    if *self.fail.borrow() { INT_ERR } else { INT_CMD_DONE | INT_XFER_DONE | INT_BUF_RD_RDY | INT_BUF_WR_RDY }
                }
                PRESENT_STATE => 0,
                RESP0 => self.regs.borrow()[ARG1 / 4] & 0xFF,
                BUF_DATA => {
                    let mut c = self.ctr.borrow_mut();
                    *c += 1;
                    *c
                }
                _ => self.regs.borrow()[o / 4],
            }
        }
        fn w8(&self, o: usize, v: u8) {
            self.writes.borrow_mut().push((o, v as u32));
        }
        fn w16(&self, o: usize, v: u16) {
            self.writes.borrow_mut().push((o, v as u32));
        }
        fn w32(&self, o: usize, v: u32) {
            if o == BUF_DATA {
                self.data_out.borrow_mut().push(v);
            } else if o == ARG1 {
                self.regs.borrow_mut()[o / 4] = v;
            }
            self.writes.borrow_mut().push((o, v));
        }
    }

    #[test]
    fn cmd52_encodes_the_argument_and_returns_the_byte() {
        let mut b = Bus::new(Fake::new());
        assert_eq!(b.cmd52(true, 1, SB_ADDR_LOW, 0xAB), Some(0xAB));
        let arg = b.m.regs.borrow()[ARG1 / 4];
        assert_eq!(arg, (1 << 31) | (1 << 28) | (1 << 27) | (SB_ADDR_LOW << 9) | 0xAB);
        let cmdw = b.m.writes.borrow().iter().rev().find(|w| w.0 == CMD_XFER + 2).unwrap().1;
        assert_eq!(cmdw as u16, (CMD52_IO_RW_DIRECT << 8) | RESP_48 | CMD_CRC_CHK | CMD_IDX_CHK);
    }

    #[test]
    fn reads_and_writes_move_whole_words_in_order() {
        let mut b = Bus::new(Fake::new());
        let mut out = [0u8; 8];
        assert!(b.cmd53_read(2, 0x8000, &mut out));
        assert_eq!(out, [1, 0, 0, 0, 2, 0, 0, 0]);
        let mut blk = [0u8; 1024];
        assert!(b.cmd53_read_blocks(2, 0x8000, &mut blk, 2, 512));
        assert_eq!(&blk[..4], &3u32.to_le_bytes());
        assert!(b.cmd53_write(1, 0x8000, &[1, 2, 3, 4, 5]));
        assert_eq!(&b.m.data_out.borrow()[..], &[0x0403_0201, 0x05]);
        assert!(b.cmd53_write_blocks(2, 0x8000, &[7u8; 128], 2, 64));
        assert_eq!(b.m.data_out.borrow().len(), 2 + 32);
    }

    #[test]
    fn failures_and_radio_off() {
        let mut b = Bus::new(Fake::new());
        *b.m.fail.borrow_mut() = true;
        assert_eq!(b.cmd52(false, 1, 0, 0), None);
        assert_eq!(b.sdio_diag.1, INT_ERR);
        assert!(!b.cmd53_write(1, 0, &[1]));
        assert_eq!(b.cmd53_diag.0, 1);
        *b.m.fail.borrow_mut() = false;
        b.off = true;
        assert_eq!(b.cmd52(false, 1, 0, 0), None, "radio off: the bus is never touched");
        assert!(!b.cmd53_read_blocks(2, 0, &mut [0u8; 8], 1, 512), "a short buffer is refused");
    }
}
