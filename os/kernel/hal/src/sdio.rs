// SPDX-License-Identifier: AGPL-3.0-only
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

/// ADR 0067 E1b: what the bus did (counts only — EL0 has no timer on the CM5; the kernel times each call and divides).
/// `wait_spins` = INT_STATUS polls spent waiting for a command / data / transfer-done bit (a proxy for bus wait time);
/// `dry_reads` = F2 first reads that found no frame (a poll that cost a CMD53 for nothing).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct BusStats {
    pub cmd52: u32,
    pub cmd53_rd: u32,
    pub cmd53_wr: u32,
    pub blk_rd: u32,
    pub blk_wr: u32,
    pub bytes_rd: u64,
    pub bytes_wr: u64,
    pub wait_spins: u64,
    pub inhibit_spins: u64,
    pub frames: u32,
    pub dry_reads: u32,
}

impl BusStats {
    /// Encoded size (the el0-wifi `CMD_BUS_STATS` reply).
    pub const LEN: usize = 64;
    pub fn encode(&self, o: &mut [u8; Self::LEN]) {
        o.fill(0);
        let w32 = [self.cmd52, self.cmd53_rd, self.cmd53_wr, self.blk_rd, self.blk_wr, self.frames, self.dry_reads];
        for (i, v) in w32.iter().enumerate() {
            o[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        for (i, v) in [self.bytes_rd, self.bytes_wr, self.wait_spins, self.inhibit_spins].iter().enumerate() {
            o[28 + i * 8..36 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::LEN {
            return None;
        }
        let u = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let q = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
        Some(BusStats { cmd52: u(0), cmd53_rd: u(4), cmd53_wr: u(8), blk_rd: u(12), blk_wr: u(16), frames: u(20), dry_reads: u(24),
            bytes_rd: q(28), bytes_wr: q(36), wait_spins: q(44), inhibit_spins: q(52) })
    }
    /// `self - earlier`, saturating (a server restart resets the counters: the delta is then 0, never a wrap).
    pub fn since(&self, e: &Self) -> Self {
        BusStats {
            cmd52: self.cmd52.saturating_sub(e.cmd52), cmd53_rd: self.cmd53_rd.saturating_sub(e.cmd53_rd),
            cmd53_wr: self.cmd53_wr.saturating_sub(e.cmd53_wr), blk_rd: self.blk_rd.saturating_sub(e.blk_rd),
            blk_wr: self.blk_wr.saturating_sub(e.blk_wr), bytes_rd: self.bytes_rd.saturating_sub(e.bytes_rd),
            bytes_wr: self.bytes_wr.saturating_sub(e.bytes_wr), wait_spins: self.wait_spins.saturating_sub(e.wait_spins),
            inhibit_spins: self.inhibit_spins.saturating_sub(e.inhibit_spins), frames: self.frames.saturating_sub(e.frames),
            dry_reads: self.dry_reads.saturating_sub(e.dry_reads),
        }
    }
}

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
    /// Bench fault injection only (ADR 0065 S4, `wifi-inject`; el0-wifi `CMD_INJECT_CMD53_STALL`): the next CMD53
    /// read is issued and then never completes — the caller's excursion budget is the only way out. Never set by the
    /// kernel's own bus, and reset with the server's writable pages after its restart.
    pub stall_next_cmd53: bool,
    /// E1b: what the bus did since this instance started (counts only).
    pub stats: BusStats,
}

impl<M: Mmio> Bus<M> {
    pub const fn new(m: M) -> Self {
        Bus { m, off: false, sdio_diag: (0, 0), cmd53_diag: (0, 0, 0), blk_diag: 0, stall_next_cmd53: false, stats: BusStats {
            cmd52: 0, cmd53_rd: 0, cmd53_wr: 0, blk_rd: 0, blk_wr: 0, bytes_rd: 0, bytes_wr: 0, wait_spins: 0, inhibit_spins: 0, frames: 0, dry_reads: 0 } }
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
            self.stats.inhibit_spins += 1;
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
            self.stats.wait_spins += 1;
            if spin > 1_000_000 {
                self.sdio_diag = (m.r32(PRESENT_STATE), st);
                return None;
            }
        }
        Some(m.r32(RESP0))
    }

    /// CMD52 (IO_RW_DIRECT): one byte on function `fnum`; returns the read / echoed byte.
    pub fn cmd52(&mut self, write: bool, fnum: u32, addr: u32, val: u8) -> Option<u8> {
        self.stats.cmd52 += 1;
        let arg = ((write as u32) << 31) | ((fnum & 7) << 28) | ((write as u32) << 27) | ((addr & 0x1_FFFF) << 9) | (val as u32);
        self.cmd(CMD52_IO_RW_DIRECT, arg, RESP_48, true, false).map(|r| (r & 0xFF) as u8)
    }

    fn wait(&mut self, bit: u32, limit: u32) -> Result<(), u32> {
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
            self.stats.wait_spins += 1;
            if spin > limit {
                return Err(st);
            }
        }
    }

    /// CMD53 byte-mode read (<= 512 B). F2 (the WLAN FIFO) is read at a FIXED address, F1 incrementing (brcmfmac).
    pub fn cmd53_read(&mut self, fnum: u32, addr: u32, out: &mut [u8]) -> bool {
        let n = out.len().min(512);
        self.stats.cmd53_rd += 1;
        self.stats.bytes_rd += n as u64;
        self.m.w16(BLK_SIZE_CNT, n as u16);
        self.m.w16(BLK_SIZE_CNT + 2, 1);
        self.m.w16(CMD_XFER, XM_READ | XM_BLKCNT_EN);
        let incr: u32 = if fnum == 2 { 0 } else { 1 };
        let arg = ((fnum & 7) << 28) | (incr << 26) | ((addr & 0x1_FFFF) << 9) | (n as u32 & 0x1FF);
        if self.cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
            return false;
        }
        if self.stall_next_cmd53 {
            // S4 injection: stuck inside this CMD53 — issued, its data never drained (the controller is left
            // mid-transfer for the restarted server to recover)
            loop {
                let _ = self.m.r32(PRESENT_STATE);
                core::hint::spin_loop();
            }
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
        self.stats.cmd53_wr += 1;
        self.stats.bytes_wr += n as u64;
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
        self.stats.blk_rd += 1;
        self.stats.bytes_rd += need as u64;
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
        self.stats.blk_wr += 1;
        self.stats.bytes_wr += need as u64;
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

    /// Write `data` to backplane address `addr` through the F1 window (firmware / NVRAM download): one 64-B block per
    /// CMD53 for the bulk (the multi-block PIO flow stalls on this card: DAT_INHIBIT held, no second BUF_WR_RDY), a
    /// byte-mode CMD53 for a tail under one block, the window re-pointed at every 32 KiB edge. Shared by the kernel
    /// and `el0-wifi` (ADR 0065 step 4e: the download's bus writes run in the server when it is loaded).
    pub fn backplane_write(&mut self, mut addr: u32, data: &[u8], fbs: usize) -> bool {
        let mut off = 0usize;
        while off < data.len() {
            if !self.set_backplane_window(addr) {
                return false;
            }
            let win_off = (addr & 0x7FFF) as usize;
            let avail = (data.len() - off).min(0x8000 - win_off);
            let n = if avail >= fbs { fbs } else { avail };
            let ok = if avail >= fbs {
                self.cmd53_write_blocks(1, (win_off as u32) | 0x8000, &data[off..off + n], 1, fbs)
            } else {
                self.cmd53_write(1, (win_off as u32) | 0x8000, &data[off..off + n])
            };
            if !ok {
                return false;
            }
            off += n;
            addr += n as u32;
        }
        true
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

// ---- step 4b-2: reading one SDPCM frame off F2 (the RX path el0-wifi runs) ----
/// The first read of every frame: hardware tag + software header + the start of the payload (brcmfmac FIRSTREAD).
pub const FIRSTREAD: usize = 64;
/// The F2 (WLAN data) FIFO address.
pub const F2_ADDR: u32 = 0x8000;
/// The SDIO core's interrupt status (backplane offset from the core base) and its mailbox bit.
pub const SD_REG_INTSTATUS: u32 = 0x20;
pub const I_HMB_HOST_INT: u32 = 1 << 7;

/// What one `read_frame` found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxRead {
    /// No frame waiting.
    Dry,
    /// The firmware raised its mailbox interrupt (the status is already cleared): handle the mailbox, then call
    /// again with `skip_int`. Only when no `hostmail` callback was given (el0-wifi asks the kernel).
    HostInt,
    /// A corrupt hardware tag / data offset (`crate::sdpcm_hdr`): the frame was terminated in the device.
    BadHdr { drained: bool },
    /// The remainder could not be read: 8 = longer than the buffer, 9 = a block read failed, 10 = a byte read
    /// failed. The frame was terminated (and the transfer aborted).
    Short { why: u8, hw_len: u16, chan: u8, drained: bool },
    /// A frame: its checked header, the valid length (clamped to the bytes really read), and whether the remainder
    /// was read in block mode.
    Frame { hdr: crate::SdpcmHdr, len: u16, block: bool },
}

impl<M: Mmio> Bus<M> {
    /// ADR 0065 claims (metal C1/C5): an EL0 bus server killed INSIDE a CMD53 leaves the controller mid-transfer —
    /// CMD/DAT inhibit set, a half-read F2 frame in the device. Every later command then spins on the inhibit past the
    /// restarted server's budget (a fault cascade). If, and only if, the controller still shows an inhibit: soft-reset
    /// the CMD and DAT lines, then abort F2 and terminate the half-read frame. Nothing in flight -> nothing done (a blind
    /// terminate drops a good frame: step 4d). 0 = nothing in flight, 1 = recovered, 2 = the reset did not clear.
    pub fn recover_abandoned(&mut self) -> u8 {
        if self.off || self.m.r32(PRESENT_STATE) & (CMD_INHIBIT | DAT_INHIBIT) == 0 {
            return 0;
        }
        self.m.w8(0x2F, RST_CMD | RST_DAT);
        let mut rs = 0u32;
        while self.m.r8(0x2F) & (RST_CMD | RST_DAT) != 0 && rs < 200_000 {
            rs += 1;
        }
        self.m.w32(INT_STATUS, 0xFFFF_FFFF);
        let cleared = self.m.r32(PRESENT_STATE) & (CMD_INHIBIT | DAT_INHIBIT) == 0;
        let _ = self.rxfail(true);
        if cleared { 1 } else { 2 }
    }

    /// brcmf_sdio_rxfail: terminate the current frame in the device (`abort` = also abort the F2 transfer, after a
    /// read error), then wait for its byte count to drain. Returns whether it drained.
    pub fn rxfail(&mut self, abort: bool) -> bool {
        const SDIO_CCCR_ABORT: u32 = 0x06;
        const SBSDIO_FUNC1_FRAMECTRL: u32 = 0x1000D;
        const SFC_RF_TERM: u8 = 1 << 0;
        const SBSDIO_FUNC1_RFRAMEBCLO: u32 = 0x1001B;
        const SBSDIO_FUNC1_RFRAMEBCHI: u32 = 0x1001C;
        if abort {
            let _ = self.cmd52(true, 0, SDIO_CCCR_ABORT, 2);
        }
        let _ = self.cmd52(true, 1, SBSDIO_FUNC1_FRAMECTRL, SFC_RF_TERM);
        for _ in 0..0xffffu32 {
            let hi = self.cmd52(false, 1, SBSDIO_FUNC1_RFRAMEBCHI, 0).unwrap_or(0xff);
            let lo = self.cmd52(false, 1, SBSDIO_FUNC1_RFRAMEBCLO, 0).unwrap_or(0xff);
            if hi == 0 && lo == 0 {
                return true;
            }
        }
        false
    }

    /// Read ONE frame off F2 into `rx`, exactly as the driver did inline: poll / clear the SDIO core's interrupt
    /// status (the mailbox interrupt goes to `hostmail`, or is returned as `HostInt`), the 64-B first read, the
    /// header check, the remainder in one transfer (block mode when `block_rx` and > 512 B; the firmware expects it
    /// whole), the unread tail zeroed (audit M-3 / L-15: never a previous frame's bytes). `max_dry` = dry polls,
    /// `delay_1ms` between them. `sdb` = the SDIO core's backplane base.
    #[allow(clippy::too_many_arguments)]
    pub fn read_frame(&mut self, sdb: u32, rx: &mut [u8], max_dry: u32, skip_int: bool, block_rx: bool,
        mut hostmail: Option<&mut dyn FnMut(&mut Self)>, delay_1ms: &mut dyn FnMut()) -> RxRead {
        let mut skip = skip_int;
        let mut waited = 0u32;
        loop {
            if !skip {
                let intstat = self.bp_r32(sdb + SD_REG_INTSTATUS);
                if intstat != 0 {
                    let _ = self.bp_w32(sdb + SD_REG_INTSTATUS, intstat);
                    if intstat & I_HMB_HOST_INT != 0 {
                        match hostmail.as_mut() {
                            Some(h) => h(self),
                            None => return RxRead::HostInt,
                        }
                    }
                }
            }
            skip = false;
            let ok = self.cmd53_read(2, F2_ADDR, &mut rx[..FIRSTREAD]);
            let (l, c) = (u16::from_le_bytes([rx[0], rx[1]]), u16::from_le_bytes([rx[2], rx[3]]));
            if ok && (l != 0 || c != 0) {
                break;
            }
            self.stats.dry_reads += 1;
            waited += 1;
            if waited > max_dry {
                return RxRead::Dry;
            }
            delay_1ms();
        }
        let hdr = match crate::sdpcm_hdr(&rx[..FIRSTREAD]) {
            Ok(Some(h)) => h,
            Ok(None) => return RxRead::Dry,
            Err(_) => return RxRead::BadHdr { drained: self.rxfail(false) },
        };
        let hw_len = hdr.len;
        self.stats.frames += 1;
        let mut valid = FIRSTREAD;
        let mut block = false;
        if (hw_len as usize) > FIRSTREAD {
            let rest = ((hw_len as usize) - FIRSTREAD + 3) & !3;
            let end = (FIRSTREAD + rest).min(rx.len());
            let want = end - FIRSTREAD;
            let got = if block_rx && want > 512 {
                let nblk = want.div_ceil(512);
                let need = nblk * 512;
                if FIRSTREAD + need <= rx.len() && self.cmd53_read_blocks(2, F2_ADDR, &mut rx[FIRSTREAD..FIRSTREAD + need], nblk as u32, 512) {
                    block = true;
                    want
                } else {
                    0
                }
            } else {
                let n = if block_rx { want } else { want.min(512) };
                if self.cmd53_read(2, F2_ADDR, &mut rx[FIRSTREAD..FIRSTREAD + n]) { n } else { 0 }
            };
            for b in rx[FIRSTREAD + got..end].iter_mut() {
                *b = 0;
            }
            valid = FIRSTREAD + got;
            if got < want || FIRSTREAD + rest > rx.len() {
                let why = if FIRSTREAD + rest > rx.len() { 8 } else if want > 512 { 9 } else { 10 };
                return RxRead::Short { why, hw_len, chan: hdr.chan, drained: self.rxfail(true) };
            }
        }
        RxRead::Frame { hdr, len: hw_len.min(valid as u16), block }
    }
}

// ---- step 4c: writing one SDPCM data frame to F2 (the TX path el0-wifi runs) ----
/// The data frame buffer: a 1514-B ethernet frame + the 16-B SDPCM / BDC header, padded to whole 512-B blocks.
pub const DATA_TX_BUF: usize = 4 * 512;
const SDPCM_DATA_CHANNEL: u32 = 2;
const SDPCM_HDRLEN: usize = 12;

/// Build one SDPCM data frame (HW tag, SW header with `seq`, the BDC header for interface `ifidx`, the ethernet
/// frame). Returns the SDPCM length (header included); `out` is the whole buffer, its tail stays zero.
pub fn data_frame(seq: u8, ifidx: u8, eth: &[u8], out: &mut [u8; DATA_TX_BUF]) -> usize {
    out.fill(0);
    let w0: u32 = (seq as u32) | (SDPCM_DATA_CHANNEL << 8) | ((SDPCM_HDRLEN as u32) << 24);
    let bdc = SDPCM_HDRLEN;
    out[bdc] = 0x20; // BDC flags: proto ver 2 << 4
    out[bdc + 2] = ifidx & 0x0f; // flags2 = destination interface (0 = primary BSS)
    let body = bdc + 4;
    let n = eth.len().min(out.len() - body);
    out[body..body + n].copy_from_slice(&eth[..n]);
    let total = (body + n) as u16;
    out[0..2].copy_from_slice(&total.to_le_bytes());
    out[2..4].copy_from_slice(&(!total).to_le_bytes());
    out[4..8].copy_from_slice(&w0.to_le_bytes());
    total as usize
}

/// What one `write_frame` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxWrite {
    /// Sent: `block` = the frame went as whole 512-B blocks (+ a byte-mode tail).
    Sent { block: bool },
    /// Longer than one byte-mode CMD53 and block TX is off in this build (refused; the caller counts it).
    TooBig,
    /// A block-mode write failed (`block` = true) or a byte-mode write failed.
    Failed { block: bool },
}

impl<M: Mmio> Bus<M> {
    /// Write ONE SDPCM frame (`frame[..len]`, padded to 4 B) to F2 exactly as the driver did inline:
    /// - <= 512 B: one byte-mode CMD53 at 0x8000;
    /// - larger, `big_tx`: whole 512-B blocks in ONE block-mode CMD53 at 0x8000, then the 4-B-aligned tail as a
    ///   byte-mode CMD53 at the ADVANCED address 0x8000 + N*512 (the Linux sequence on this CM5; never a padding
    ///   block, never a chunk restarted at 0x8000 — both wedged or desynced the firmware on metal);
    /// - larger, no `big_tx`: refused (split byte-mode chunks desync the firmware's SDPCM stream).
    pub fn write_frame(&mut self, frame: &[u8], len: usize, big_tx: bool) -> TxWrite {
        let padded = (len + 3) & !3;
        if padded > frame.len() {
            return TxWrite::Failed { block: padded > 512 };
        }
        if padded <= 512 {
            return if self.cmd53_write(2, F2_ADDR, &frame[..padded]) { TxWrite::Sent { block: false } } else { TxWrite::Failed { block: false } };
        }
        if !big_tx {
            return TxWrite::TooBig;
        }
        let nblk = padded / 512;
        let rem = padded % 512;
        let mut ok = self.cmd53_write_blocks(2, F2_ADDR, &frame[..nblk * 512], nblk as u32, 512);
        if ok && rem > 0 {
            ok = self.cmd53_write(2, F2_ADDR + (nblk * 512) as u32, &frame[nblk * 512..padded]);
        }
        if ok { TxWrite::Sent { block: true } } else { TxWrite::Failed { block: true } }
    }

    /// brcmfmac's TX-error path (brcmf_sdio_txpkt -> abort F2, SFC_WF_TERM, wait for WFRAMEBC to drain): used after
    /// a write that may have been cut off part-way (el0-wifi faulted inside it). Returns whether it drained.
    pub fn txfail(&mut self) -> bool {
        const SDIO_CCCR_ABORT: u32 = 0x06;
        const SBSDIO_FUNC1_FRAMECTRL: u32 = 0x1000D;
        const SFC_WF_TERM: u8 = 1 << 1;
        const SBSDIO_FUNC1_WFRAMEBCLO: u32 = 0x10019;
        const SBSDIO_FUNC1_WFRAMEBCHI: u32 = 0x1001A;
        let _ = self.cmd52(true, 0, SDIO_CCCR_ABORT, 2);
        let _ = self.cmd52(true, 1, SBSDIO_FUNC1_FRAMECTRL, SFC_WF_TERM);
        for _ in 0..0xffu32 {
            let hi = self.cmd52(false, 1, SBSDIO_FUNC1_WFRAMEBCHI, 0).unwrap_or(0xff);
            let lo = self.cmd52(false, 1, SBSDIO_FUNC1_WFRAMEBCLO, 0).unwrap_or(0xff);
            if hi == 0 && lo == 0 {
                return true;
            }
        }
        false
    }
}


/// ADR 0067 E1 — the vectored read: up to `i.max` SDPCM frames off the bus, each pushed whole to the RX ring, in one
/// call. One poll per frame and never a wait (as the single-frame read in el0-wifi). The batch ends at its size, at a
/// dry device, at the mailbox interrupt (the kernel's to handle), at a frame that could not be read whole, or when the
/// ring is full — and says which. A frame taken off the bus and not delivered is `attempted - produced`.
pub fn read_frames<M: Mmio, R: crate::el0ring::RingMem + ?Sized>(bus: &mut Bus<M>, ring: &mut R, i: &crate::wifisrvabi::rxvmsg::In) -> crate::wifisrvabi::rxvmsg::Out {
    use crate::wifisrvabi::{rxvmsg::Out, VecStop};
    let mut buf = [0u8; 2048];
    let cap = (i.cap as usize).clamp(FIRSTREAD, crate::el0ring::FRAME_MAX.min(buf.len()));
    let mut o = Out { produced: 0, attempted: 0, stop: VecStop::Limit, drained: false, blk_diag: 0 };
    let mut skip = i.skip_int;
    while o.produced < i.max {
        let r = bus.read_frame(i.sdb, &mut buf[..cap], 0, skip, i.block_rx, None, &mut || {});
        skip = false;
        match r {
            RxRead::Dry => {
                o.stop = VecStop::Drained;
                break;
            }
            RxRead::HostInt => {
                o.stop = VecStop::HostInt;
                break;
            }
            RxRead::BadHdr { drained } => {
                o.attempted += 1;
                o.stop = VecStop::BadFrame;
                o.drained = drained;
                break;
            }
            RxRead::Short { drained, .. } => {
                o.attempted += 1;
                o.stop = VecStop::BusError;
                o.drained = drained;
                break;
            }
            RxRead::Frame { len, .. } => {
                o.attempted += 1;
                let n = (len as usize).max(FIRSTREAD).min(cap);
                if crate::el0ring::push(ring, &buf[..n]) {
                    o.produced += 1;
                } else {
                    o.stop = VecStop::Ring;
                    break;
                }
            }
        }
    }
    o.blk_diag = bus.blk_diag;
    o
}

/// ADR 0067 E1 — the vectored write: pop up to `n` slots from the TX ring (`txvmsg::slot_encode`), build each SDPCM data
/// frame with the sequence the kernel assigned and write it to F2, in one call. The batch ends at its size, at an empty
/// ring, at a malformed slot or a frame this build cannot send, or at the first failed bus write — and says which.
/// `popped - sent` frames left the ring without reaching the device (at most one: the batch stops there).
pub fn write_frames<M: Mmio, R: crate::el0ring::RingMem + ?Sized>(bus: &mut Bus<M>, ring: &mut R, n: u8) -> crate::wifisrvabi::txvmsg::Out {
    use crate::wifisrvabi::{txvmsg, VecStop};
    let mut o = txvmsg::Out { popped: 0, sent: 0, stop: VecStop::Limit, status: 0 };
    let mut slot = [0u8; crate::el0ring::FRAME_MAX];
    let mut frame = [0u8; DATA_TX_BUF];
    while o.popped < n {
        let len = match crate::el0ring::pop(ring, &mut slot) {
            crate::el0ring::Pop::Frame(len) => len,
            crate::el0ring::Pop::Empty => {
                o.stop = VecStop::Drained;
                break;
            }
            crate::el0ring::Pop::Bad => {
                o.stop = VecStop::Ring;
                break;
            }
        };
        o.popped += 1;
        let Some((seq, ifidx, big, eth)) = txvmsg::slot_decode(&slot[..len]) else {
            o.stop = VecStop::BadFrame;
            break;
        };
        let total = data_frame(seq, ifidx, eth, &mut frame);
        match bus.write_frame(&frame, total, big) {
            TxWrite::Sent { block } => {
                o.sent += 1;
                o.status |= block as u32; // bit 0: a frame of this batch went in block mode
            }
            TxWrite::TooBig => {
                o.stop = VecStop::BadFrame;
                break;
            }
            TxWrite::Failed { block } => {
                o.stop = VecStop::BusError;
                o.status |= 2 | (block as u32) << 2; // bit 1: a write failed; bit 2: it was a block-mode write
                break;
            }
        }
    }
    o
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
        /// When non-empty, BUF_DATA reads come from here (a frame in the F2 FIFO).
        fifo: RefCell<std::collections::VecDeque<u32>>,
    }
    impl Fake {
        fn new() -> Self {
            Fake { regs: RefCell::new([0; 64]), writes: RefCell::new(Vec::new()), data_out: RefCell::new(Vec::new()), ctr: RefCell::new(0), fail: RefCell::new(false), fifo: RefCell::new(Default::default()) }
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
                BUF_DATA if !self.fifo.borrow().is_empty() => self.fifo.borrow_mut().pop_front().unwrap_or(0),
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
    fn backplane_write_moves_every_byte_in_order_across_a_window_edge() {
        // 64 B before a 32 KiB window edge: one block there, then a block and a 10-B byte-mode tail past the edge
        let mut b = Bus::new(Fake::new());
        let data: Vec<u8> = (0..138u32).map(|i| (i * 7 + 3) as u8).collect();
        assert!(b.backplane_write(0x0001_7FC0, &data, 64));
        let out: Vec<u8> = b.m.data_out.borrow().iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(&out[..data.len()], &data[..]);
        // the window was pointed once per CMD53 (3 writes x 3 CMD52 bytes), the last at the next 32 KiB window
        let win: Vec<u32> = b.m.writes.borrow().iter().filter(|w| w.0 == ARG1 && (w.1 >> 28) & 7 == 1 && (w.1 >> 31) == 1 && ((w.1 >> 9) & 0x1FFFF) == SB_ADDR_MID).map(|w| w.1 & 0xFF).collect();
        assert_eq!(win.len(), 3);
        assert_eq!(*win.last().unwrap(), 0x01);
        // a failing bus stops the download
        let mut f = Bus::new(Fake::new());
        *f.m.fail.borrow_mut() = true;
        assert!(!f.backplane_write(0x0001_8000, &data, 64));
    }

    #[test]
    fn bus_stats_encode_round_trip_and_since() {
        let a = BusStats { cmd52: 1, cmd53_rd: 2, cmd53_wr: 3, blk_rd: 4, blk_wr: 5, bytes_rd: 6_000_000_000, bytes_wr: 7, wait_spins: 8, inhibit_spins: 9, frames: 10, dry_reads: 11 };
        let mut b = [0u8; BusStats::LEN];
        a.encode(&mut b);
        assert_eq!(BusStats::decode(&b), Some(a));
        assert_eq!(BusStats::decode(&b[..BusStats::LEN - 1]), None);
        let z = BusStats::default();
        assert_eq!(a.since(&z), a);
        assert_eq!(z.since(&a), z); // a restart reset the counters: 0, never a wrap
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


    fn frame(len: u16, chan: u8, doff: u8, fill: u8) -> std::vec::Vec<u32> {
        let mut b = std::vec![fill; len as usize];
        b[0..2].copy_from_slice(&len.to_le_bytes());
        b[2..4].copy_from_slice(&(!len).to_le_bytes());
        b[4..8].copy_from_slice(&(3u32 | (chan as u32) << 8 | (doff as u32) << 24).to_le_bytes());
        b[8..12].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
    }

    #[test]
    fn read_frame_reads_header_then_remainder() {
        let mut b = Bus::new(Fake::new());
        *b.m.fifo.borrow_mut() = frame(300, 2, 14, 0xab).into();
        let mut rx = [0u8; 2048];
        match b.read_frame(0x1800_2000, &mut rx, 0, false, false, None, &mut || {}) {
            RxRead::Frame { hdr, len, block } => {
                assert_eq!((hdr.chan, hdr.doff, hdr.len, len, block), (2, 14, 300, 300, false));
                assert!(rx[64..300].iter().all(|&x| x == 0xab));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn read_frame_dry_and_bad_header() {
        let mut b = Bus::new(Fake::new());
        let mut rx = [0u8; 2048];
        *b.m.fifo.borrow_mut() = std::vec![0u32; 16].into();
        assert_eq!(b.read_frame(0, &mut rx, 0, false, false, None, &mut || {}), RxRead::Dry);
        let mut bad = frame(100, 2, 14, 1);
        bad[0] ^= 0x0001_0000; // break the check word
        *b.m.fifo.borrow_mut() = bad.into();
        assert!(matches!(b.read_frame(0, &mut rx, 0, false, false, None, &mut || {}), RxRead::BadHdr { .. }));
    }

    #[test]
    fn read_frames_moves_a_batch_into_the_ring_and_says_why_it_stopped() {
        use crate::el0ring as ring;
        use crate::wifisrvabi::{rxvmsg, VecStop};
        let mut mem = std::vec![0u8; ring::RING_BYTES];
        ring::reset(&mut mem[..]);
        let ask = |max: u8| rxvmsg::In { sdb: 0x1800_2000, skip_int: false, block_rx: false, max, cap: 2044 };
        // three frames in the FIFO, then nothing: a batch of 8 delivers three and reports the device drained
        let mut b = Bus::new(Fake::new());
        let mut q: Vec<u32> = Vec::new();
        for (len, fill) in [(300u16, 0xa1u8), (400, 0xb2), (92, 0xc3)] {
            q.extend(frame(len, 2, 14, fill));
        }
        q.extend(std::vec![0u32; 16]);
        *b.m.fifo.borrow_mut() = q.into();
        let o = read_frames(&mut b, &mut mem[..], &ask(8));
        assert_eq!((o.produced, o.attempted, o.stop), (3, 3, VecStop::Drained));
        assert_eq!(ring::pending(&mem[..]), 3);
        let mut out = [0u8; 2048];
        assert_eq!(ring::pop(&mut mem[..], &mut out), ring::Pop::Frame(300));
        assert!(out[64..300].iter().all(|&x| x == 0xa1));
        assert_eq!(ring::pop(&mut mem[..], &mut out), ring::Pop::Frame(400));
        assert!(out[64..400].iter().all(|&x| x == 0xb2));
        assert_eq!(ring::pop(&mut mem[..], &mut out), ring::Pop::Frame(92));
        // the batch size is a hard limit: two of three, the third stays in the device
        let mut q: Vec<u32> = Vec::new();
        for fill in [1u8, 2, 3] {
            q.extend(frame(200, 2, 14, fill));
        }
        *b.m.fifo.borrow_mut() = q.into();
        let o = read_frames(&mut b, &mut mem[..], &ask(2));
        assert_eq!((o.produced, o.attempted, o.stop), (2, 2, VecStop::Limit));
        // a bad header ends the batch: the good frame before it is delivered, the bad one counted as attempted
        ring::reset(&mut mem[..]);
        let mut q: Vec<u32> = frame(120, 2, 14, 9);
        let mut bad = frame(100, 2, 14, 1);
        bad[0] ^= 0x0001_0000;
        q.extend(bad);
        *b.m.fifo.borrow_mut() = q.into();
        let o = read_frames(&mut b, &mut mem[..], &ask(8));
        assert_eq!((o.produced, o.attempted, o.stop), (1, 2, VecStop::BadFrame));
        // a full ring ends the batch and the frame that did not fit is counted lost (attempted - produced)
        ring::reset(&mut mem[..]);
        for _ in 0..ring::SLOTS - 1 {
            if !ring::push(&mut mem[..], &[0u8; 64]) {
                break;
            }
        }
        let room = ring::SLOTS - ring::pending(&mem[..]);
        let mut q: Vec<u32> = Vec::new();
        for fill in [1u8, 2, 3] {
            q.extend(frame(200, 2, 14, fill));
        }
        *b.m.fifo.borrow_mut() = q.into();
        let o = read_frames(&mut b, &mut mem[..], &ask(8));
        assert!(o.stop == VecStop::Ring && o.produced as usize == room && o.attempted == o.produced + 1, "{o:?} room {room}");
    }

    #[test]
    fn read_frame_too_long_for_the_buffer_is_short() {
        let mut b = Bus::new(Fake::new());
        *b.m.fifo.borrow_mut() = frame(1500, 2, 14, 7).into();
        let mut rx = [0u8; 600];
        assert!(matches!(b.read_frame(0, &mut rx, 0, false, false, None, &mut || {}), RxRead::Short { why: 8, .. }));
    }


    #[test]
    fn data_frame_layout() {
        let mut f = [0xffu8; DATA_TX_BUF];
        let eth = [0x11u8; 60];
        let n = data_frame(7, 1, &eth, &mut f);
        assert_eq!(n, 76);
        assert_eq!(u16::from_le_bytes([f[0], f[1]]), 76);
        assert_eq!(u16::from_le_bytes([f[2], f[3]]), !76u16);
        assert_eq!(u32::from_le_bytes([f[4], f[5], f[6], f[7]]), 7 | 2 << 8 | 12 << 24);
        assert_eq!((f[12], f[13], f[14], f[15]), (0x20, 0, 1, 0));
        assert!(f[16..76].iter().all(|&b| b == 0x11) && f[76..].iter().all(|&b| b == 0));
        // the receive side's checker accepts what the transmit side builds
        let h = crate::sdpcm_hdr(&f[..64]).unwrap().unwrap();
        assert_eq!((h.len, h.seq, h.chan, h.doff), (76, 7, 2, 12));
    }

    #[test]
    fn write_frame_small_big_and_refused() {
        let mut f = [0u8; DATA_TX_BUF];
        let n = data_frame(1, 0, &[0x22u8; 100], &mut f);
        let mut b = Bus::new(Fake::new());
        assert_eq!(b.write_frame(&f, n, false), TxWrite::Sent { block: false });
        assert_eq!(b.m.data_out.borrow().len() * 4, (n + 3) & !3, "one byte-mode CMD53 of the padded length");
        let n = data_frame(2, 0, &[0x33u8; 1514], &mut f);
        assert_eq!(n, 1530);
        assert_eq!(b.write_frame(&f, n, false), TxWrite::TooBig, "no block TX in this build: refused, not split");
        let mut b = Bus::new(Fake::new());
        assert_eq!(b.write_frame(&f, n, true), TxWrite::Sent { block: true });
        assert_eq!(b.m.data_out.borrow().len() * 4, 1532, "2 blocks + the 508-B tail, no padding block");
        let mut b = Bus::new(Fake::new());
        *b.m.fail.borrow_mut() = true;
        assert_eq!(b.write_frame(&f, 100, false), TxWrite::Failed { block: false });
    }

    #[test]
    fn write_frames_sends_a_batch_from_the_ring_in_order_and_stops_at_the_first_failure() {
        use crate::el0ring as ring;
        use crate::wifisrvabi::{txvmsg, VecStop};
        let mut mem = std::vec![0u8; ring::RING_BYTES];
        let fill = |mem: &mut [u8], seqs: &[u8]| {
            ring::reset(mem);
            for &q in seqs {
                let mut sl = [0u8; 2048];
                let n = txvmsg::slot_encode(q, 0, false, &[q; 100], &mut sl).unwrap();
                assert!(ring::push(mem, &sl[..n]));
            }
        };
        // three frames queued, a batch of 8: all three written, in order, with the kernel's sequence numbers
        fill(&mut mem[..], &[7, 8, 9]);
        let mut b = Bus::new(Fake::new());
        let o = write_frames(&mut b, &mut mem[..], 8);
        assert_eq!((o.popped, o.sent, o.stop), (3, 3, VecStop::Drained));
        let out: Vec<u8> = b.m.data_out.borrow().iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut one = [0u8; DATA_TX_BUF];
        let n1 = (data_frame(7, 0, &[7u8; 100], &mut one) + 3) & !3;
        assert_eq!(out.len(), 3 * n1);
        assert_eq!(&out[..n1], &one[..n1]);
        assert_eq!(out[n1 + 4], 8, "the second frame carries sequence 8");
        assert_eq!(out[2 * n1 + 4], 9);
        // the batch size is a hard limit: two written, one stays in the ring
        fill(&mut mem[..], &[1, 2, 3]);
        let o = write_frames(&mut Bus::new(Fake::new()), &mut mem[..], 2);
        assert_eq!((o.popped, o.sent, o.stop, ring::pending(&mem[..])), (2, 2, VecStop::Limit, 1));
        // a failing bus: the first write fails, the batch stops, the other frames stay queued
        fill(&mut mem[..], &[1, 2, 3]);
        let mut bad = Bus::new(Fake::new());
        *bad.m.fail.borrow_mut() = true;
        let o = write_frames(&mut bad, &mut mem[..], 8);
        assert_eq!((o.popped, o.sent, o.stop, ring::pending(&mem[..])), (1, 0, VecStop::BusError, 2));
        assert_eq!(o.status & 2, 2);
        // a malformed slot is not sent and ends the batch
        ring::reset(&mut mem[..]);
        assert!(ring::push(&mut mem[..], &[1, 0, 9, 0, 0xaa, 0xbb]));
        let o = write_frames(&mut Bus::new(Fake::new()), &mut mem[..], 8);
        assert_eq!((o.popped, o.sent, o.stop), (1, 0, VecStop::BadFrame));
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
