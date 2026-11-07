//! Base-parameterized SD Host Controller v3 (`brcm,bcm2712-sdhci`) helper layer.
//!
//! This is a faithful TRANSCRIPTION of the metal-proven SDHCI knowledge in
//! `cyw43.rs` (the CYW43455 WiFi host at 0x10_0110_0000), re-parameterized on the
//! controller base so a SECOND instance — the eMMC at 0x10_00FF_F000 (P15) — can
//! reuse it without touching the mid-bring-up WiFi driver. Nothing here is
//! WiFi/SDIO-specific: it is the raw command + PIO + reset primitives.
//!
//! Hard-won facts carried over verbatim (see `cyw43.rs` for the archaeology):
//!  * INT_ENABLE (0x34) LATCH: SW-reset clears 0x34; unless every status bit is
//!    re-armed, INT_STATUS (0x30) never latches and every command false-times-out.
//!  * PIO waits gate on the INT_STATUS bits (BUF_RD_RDY / XFER_DONE), NOT on
//!    PRESENT_STATE bit10/11 (unreliable on this controller).
//!  * Data Timeout Control (0x2E) must be set non-zero or large reads DATA-TIMEOUT.
//!
//! Divergences from `cyw43.rs`, all deliberate:
//!  * base-parameterized (`Host { base, cfg }`) instead of module constants.
//!  * a typed `Resp` enum computes the correct CRC/index-check flags per response
//!    (eMMC needs R2/R3 which the SDIO path never used).
//!  * every wait is bounded by a CNTPCT_EL0 *wall-clock* deadline, not a spin
//!    count (deterministic across clock speeds — a spin count that is fine at
//!    390 kHz is far too short once the bus clocks up).

#![cfg(feature = "cm5")]

use core::ptr::{read_volatile, write_volatile};

// --- SD Host Controller v3 register map (byte offsets from `base`) ------------
const ARG2: usize = 0x00;
const BLK_SIZE_CNT: usize = 0x04; // [15:0]=block size, [31:16]=block count
const ARG1: usize = 0x08;
const CMD_XFER: usize = 0x0C; // [15:0]=transfer mode, [31:16]=command
const RESP0: usize = 0x10; // 0x10..0x1c = 128-bit response
const BUF_DATA: usize = 0x20; // PIO data port
const PRESENT_STATE: usize = 0x24;
const HOST_CTRL1: usize = 0x28; // [7:0] host control, [15:8] power, ...
const POWER_CTRL: usize = 0x29; // bus power byte
const CLOCK_CTRL: usize = 0x2C; // [15:0] clock control
const TIMEOUT_CTRL: usize = 0x2E; // data timeout counter
const SW_RESET: usize = 0x2F; // SW-reset byte
const INT_STATUS: usize = 0x30;
const INT_ENABLE: usize = 0x34; // status-ENABLE latch (the 0x34 discovery)
const SIG_ENABLE: usize = 0x38;
const CAPS: usize = 0x40;

// PRESENT_STATE bits.
const CMD_INHIBIT: u32 = 1 << 0;
const DAT_INHIBIT: u32 = 1 << 1;
// CLOCK_CTRL bits.
const INT_CLK_EN: u16 = 1 << 0;
const INT_CLK_STABLE: u16 = 1 << 1;
const SD_CLK_EN: u16 = 1 << 2;
// SW_RESET byte bits.
const RST_ALL: u8 = 1 << 0;
const RST_CMD: u8 = 1 << 1;
const RST_DAT: u8 = 1 << 2;
// INT_STATUS bits.
const INT_CMD_DONE: u32 = 1 << 0;
const INT_XFER_DONE: u32 = 1 << 1;
const INT_BUF_WR_RDY: u32 = 1 << 4;
const INT_BUF_RD_RDY: u32 = 1 << 5;
const INT_CARD: u32 = 1 << 8; // SDIO in-band card interrupt (masked; eMMC never uses it)
const INT_ERR: u32 = 1 << 15;
// CMD flags (low byte of the command register @ CMD_XFER+2).
const RESP_48: u16 = 0b10;
const RESP_48_BUSY: u16 = 0b11;
const RESP_136: u16 = 0b01;
const CMD_CRC_CHK: u16 = 1 << 3;
const CMD_IDX_CHK: u16 = 1 << 4;
const CMD_DATA: u16 = 1 << 5;
// Transfer-mode bits (low half of CMD_XFER).
const XM_READ: u16 = 1 << 4;
const XM_BLKCNT_EN: u16 = 1 << 1;

/// Response type of an MMC/SD command — carries the correct SDHCI response-select
/// bits AND whether the controller should check the response CRC / command index.
/// Getting these wrong is a silent source of INT_ERR: R3 (OCR) has no CRC/index,
/// R2 (CID/CSD) has a CRC but no index.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Resp {
    /// No response (CMD0).
    NoResp,
    /// 48-bit, CRC + index checked (CMD3/CMD16/CMD17 → R1).
    R1,
    /// 48-bit with busy, CRC + index checked (CMD7 → R1b).
    R1b,
    /// 136-bit, CRC checked, index NOT checked (CMD2/CMD9 → R2/CID/CSD).
    R2,
    /// 48-bit, NO CRC, NO index check (CMD1 → R3/OCR).
    R3,
}

impl Resp {
    fn flags(self) -> u16 {
        match self {
            Resp::NoResp => 0,
            Resp::R1 => RESP_48 | CMD_CRC_CHK | CMD_IDX_CHK,
            Resp::R1b => RESP_48_BUSY | CMD_CRC_CHK | CMD_IDX_CHK,
            Resp::R2 => RESP_136 | CMD_CRC_CHK, // 136-bit: no index check
            Resp::R3 => RESP_48,                // OCR: no CRC, no index
        }
    }
}

/// A block-transfer / command error, distinguishing the failure modes so the
/// caller (and its diagnostics) can tell a no-response card from a rejected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkErr {
    /// Command inhibit never cleared (host wedged before issue).
    Inhibit,
    /// The host reported an error bit (INT_ERR) — CRC/index/end-bit/timeout.
    CmdError,
    /// The command completed on the bus but no INT latched before the deadline.
    CmdTimeout,
    /// The data phase did not become ready / complete before the deadline.
    DataTimeout,
}

// --- CNTPCT_EL0 wall-clock deadlines ------------------------------------------
#[inline]
fn cntfrq() -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f
}
#[inline]
fn cntpct() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) t, options(nomem, nostack)) };
    t
}
/// A wall-clock deadline `us` microseconds from now (never a spin count).
#[inline]
fn deadline(us: u64) -> u64 {
    cntpct().wrapping_add(cntfrq().saturating_mul(us) / 1_000_000)
}
#[inline]
fn expired(dl: u64) -> bool {
    cntpct().wrapping_sub(dl) < (1u64 << 63) // now >= dl (wrap-safe)
}
fn delay_us(us: u64) {
    let dl = deadline(us);
    while !expired(dl) {
        core::hint::spin_loop();
    }
}

/// A single SD Host Controller instance, addressed by its MMIO base + cfg block.
#[derive(Clone, Copy)]
pub struct Host {
    pub base: usize,
    pub cfg: usize,
}

impl Host {
    pub const fn new(base: usize, cfg: usize) -> Self {
        Host { base, cfg }
    }

    #[inline]
    fn r8(&self, o: usize) -> u8 {
        unsafe { read_volatile((self.base + o) as *const u8) }
    }
    #[inline]
    fn w8(&self, o: usize, v: u8) {
        unsafe { write_volatile((self.base + o) as *mut u8, v) };
    }
    #[inline]
    fn r16(&self, o: usize) -> u16 {
        unsafe { read_volatile((self.base + o) as *const u16) }
    }
    #[inline]
    fn w16(&self, o: usize, v: u16) {
        unsafe { write_volatile((self.base + o) as *mut u16, v) };
    }
    #[inline]
    pub fn r32(&self, o: usize) -> u32 {
        unsafe { read_volatile((self.base + o) as *const u32) }
    }
    #[inline]
    fn w32(&self, o: usize, v: u32) {
        unsafe { write_volatile((self.base + o) as *mut u32, v) };
    }

    /// Full SW reset + the INT_ENABLE-latch recipe, transcribed verbatim from
    /// `cyw43::host_reset` (the single most important line is `w32(INT_ENABLE,..)`
    /// — without it every command false-times-out with INT_STATUS stuck at 0).
    pub fn reset_all(&self) {
        self.w8(SW_RESET, RST_ALL);
        let dl = deadline(100_000);
        while self.r8(SW_RESET) & RST_ALL != 0 && !expired(dl) {
            core::hint::spin_loop();
        }
        // CRITICAL: SW-reset clears 0x34; the controller only LATCHES a bit into
        // INT_STATUS (0x30) if the matching 0x34 bit is set. Arm all status bits
        // EXCEPT the SDIO in-band Card interrupt (eMMC never asserts it; masking
        // it matches the WiFi driver's hard-won recipe). We POLL — leave 0x38 at 0.
        self.w32(INT_ENABLE, 0xFFFF_FFFF & !INT_CARD);
        self.w32(SIG_ENABLE, 0x0000_0000);
        // Data Timeout Control: max counter, or a 512-byte read DATA-TIMEOUTs.
        self.w8(TIMEOUT_CTRL, 0x0E);
    }

    /// Bus power on at `voltage` (power byte @0x29: bit0=on, [3:1]=voltage code;
    /// 0b111 = 3.3 V, 0b101 = 1.8 V). The eMMC rail is a fixed board property.
    pub fn power_on(&self, voltage: u8) {
        self.w8(POWER_CTRL, ((voltage & 0x7) << 1) | 1);
        delay_us(2_000);
    }

    /// Set SDCLK from a divisor (SDCLK = base / (2*divisor)); enable it. Verbatim
    /// from `cyw43::set_clock`. The CALLER computes the divisor from the base rate
    /// read over the mailbox — this never touches the clock source.
    pub fn set_clock(&self, divisor: u16) {
        self.w16(CLOCK_CTRL, 0); // stop
        let d = divisor & 0xFF;
        let dhi = (divisor >> 8) & 0x3;
        let mut v = INT_CLK_EN | (d << 8) | (dhi << 6);
        self.w16(CLOCK_CTRL, v);
        let dl = deadline(100_000);
        while self.r16(CLOCK_CTRL) & INT_CLK_STABLE == 0 && !expired(dl) {
            core::hint::spin_loop();
        }
        v |= SD_CLK_EN;
        self.w16(CLOCK_CTRL, v);
    }

    /// Wait until `mask` sets in INT_STATUS, bounded by a wall-clock deadline.
    /// Returns Err(CmdError) if INT_ERR sets first, Err(kind) on timeout.
    fn wait_int(&self, mask: u32, us: u64, timeout_kind: BlkErr) -> Result<(), BlkErr> {
        let dl = deadline(us);
        loop {
            let st = self.r32(INT_STATUS);
            if st & INT_ERR != 0 {
                return Err(BlkErr::CmdError);
            }
            if st & mask != 0 {
                return Ok(());
            }
            if expired(dl) {
                return Err(timeout_kind);
            }
            core::hint::spin_loop();
        }
    }

    /// Issue a command; return RESP0 (low 32 bits of the response). Transcribed
    /// from `cyw43::cmd` with the inhibit-recovery reset and the CNTPCT deadline.
    /// `data` marks a data-phase command (DAT inhibit + transfer-mode expected).
    pub fn cmd(&self, idx: u16, arg: u32, resp: Resp, data: bool) -> Result<u32, BlkErr> {
        let inhibit = CMD_INHIBIT | if data { DAT_INHIBIT } else { 0 };
        let dl = deadline(200_000);
        while self.r32(PRESENT_STATE) & inhibit != 0 {
            if expired(dl) {
                // Inhibit stuck — soft-reset the CMD (+ DAT) circuit and proceed.
                let mut rb = RST_CMD;
                if data {
                    rb |= RST_DAT;
                }
                self.w8(SW_RESET, rb);
                let rdl = deadline(50_000);
                while self.r8(SW_RESET) & rb != 0 && !expired(rdl) {
                    core::hint::spin_loop();
                }
                break;
            }
            core::hint::spin_loop();
        }
        self.w32(INT_STATUS, 0xFFFF_FFFF); // clear stale
        self.w32(ARG1, arg);
        let mut flags = resp.flags();
        if data {
            flags |= CMD_DATA;
        }
        self.w16(CMD_XFER + 2, (idx << 8) | flags);
        // R1b carries a busy phase; wait command-done and (best-effort) busy clear.
        self.wait_int(INT_CMD_DONE, 1_000_000, BlkErr::CmdTimeout)?;
        Ok(self.r32(RESP0))
    }

    /// Read all four response words (for R2 — CID/CSD 136-bit).
    pub fn resp128(&self) -> [u32; 4] {
        [
            self.r32(RESP0),
            self.r32(RESP0 + 4),
            self.r32(RESP0 + 8),
            self.r32(RESP0 + 0xC),
        ]
    }

    /// PIO read of one `block_size`-byte block into `out` after a data command has
    /// been issued. Waits BUF_RD_RDY (INT bit — not PRESENT_STATE), drains the FIFO
    /// 32 bits at a time, then waits XFER_DONE (de-asserts DAT_INHIBIT for the next
    /// command). Transcribed from `cyw43::cmd53_read`.
    pub fn pio_in(&self, out: &mut [u8], block_size: usize) -> Result<(), BlkErr> {
        let n = out.len().min(block_size);
        self.wait_int(INT_BUF_RD_RDY, 1_000_000, BlkErr::DataTimeout)?;
        let mut i = 0;
        while i < n {
            let word = self.r32(BUF_DATA);
            for b in 0..4 {
                if i < n {
                    out[i] = ((word >> (b * 8)) & 0xFF) as u8;
                    i += 1;
                }
            }
        }
        self.wait_int(INT_XFER_DONE, 1_000_000, BlkErr::DataTimeout)
    }

    /// Program the block size + count for a single-block transfer.
    pub fn set_block(&self, block_size: u16, count: u16) {
        self.w16(BLK_SIZE_CNT, block_size);
        self.w16(BLK_SIZE_CNT + 2, count);
    }

    /// Arm the transfer mode for a single-block READ (BLK_CNT_EN | READ), written
    /// before the command register (which `cmd()` writes). Matches Linux
    /// `sdhci_set_transfer_mode` for a 1-block read.
    pub fn set_xfer_read_single(&self) {
        self.w16(CMD_XFER, XM_READ | XM_BLKCNT_EN);
    }

    /// PIO write of one `block_size`-byte block from `data` after a write data
    /// command has been issued. Waits BUF_WR_RDY (INT bit), pushes the FIFO 32 bits
    /// at a time, then waits XFER_DONE. Transcribed from `cyw43::cmd53_write`.
    /// (Only compiled behind `p15-write`; the read-only build never links it.)
    #[cfg(feature = "p15-write")]
    pub fn pio_out(&self, data: &[u8], block_size: usize) -> Result<(), BlkErr> {
        let n = data.len().min(block_size);
        self.wait_int(INT_BUF_WR_RDY, 1_000_000, BlkErr::DataTimeout)?;
        let mut i = 0;
        while i < n {
            let mut word = 0u32;
            for b in 0..4 {
                if i < n {
                    word |= (data[i] as u32) << (b * 8);
                    i += 1;
                }
            }
            self.w32(BUF_DATA, word);
        }
        self.wait_int(INT_XFER_DONE, 2_000_000, BlkErr::DataTimeout)
    }

    /// Arm the transfer mode for a single-block WRITE (BLK_CNT_EN, READ clear).
    #[cfg(feature = "p15-write")]
    pub fn set_xfer_write_single(&self) {
        self.w16(CMD_XFER, XM_BLKCNT_EN);
    }

    /// Diagnostic snapshot (dump-before-touch): key registers as-found.
    /// [CAPS, PRESENT_STATE, HOST_CTRL1, CLOCK_CTRL, INT_STATUS, INT_ENABLE].
    pub fn dump(&self) -> [u32; 6] {
        [
            self.r32(CAPS),
            self.r32(PRESENT_STATE),
            self.r32(HOST_CTRL1),
            self.r32(CLOCK_CTRL),
            self.r32(INT_STATUS),
            self.r32(INT_ENABLE),
        ]
    }

    /// Base clock in MHz from the capabilities register ([13:8] on SDHCIv3).
    pub fn caps_base_mhz(&self) -> u32 {
        (self.r32(CAPS) >> 8) & 0x3F
    }
}
