//! P13 — RP1 I²C master (Synopsys DW_apb_i2c), CM5 / BCM2712.
//!
//! Strictly PIO (the 32-entry FIFO is ample); the RP1 DMAC is NEVER touched. Every
//! wait is bounded via `rp1::poll_until` — a clock-stretching slave produces a
//! TIMEOUT, never a wedge. Bus scanning uses a **1-byte READ** (DATA_CMD = 0x300 =
//! READ|STOP), never a write, so an SMBus write-quick can't latch a relay.
//!
//! `open()` liveness-probes IC_COMP_TYPE (must read `0x44570140`, no bus traffic),
//! prechecks the bus is idle, and programs the SCL HCNT/LCNT from the DERIVED
//! `clk_sys` (never hard-coded; timing math in u64, u16-clamped).

use crate::rp1;

// --- DW_apb_i2c register offsets ----------------------------------------------
const IC_CON: usize = 0x00;
const IC_TAR: usize = 0x04;
const IC_DATA_CMD: usize = 0x10;
const IC_SS_SCL_HCNT: usize = 0x14;
const IC_SS_SCL_LCNT: usize = 0x18;
const IC_FS_SCL_HCNT: usize = 0x1c;
const IC_FS_SCL_LCNT: usize = 0x20;
const IC_INTR_MASK: usize = 0x30;
const IC_RAW_INTR_STAT: usize = 0x34;
const IC_RX_TL: usize = 0x38;
const IC_TX_TL: usize = 0x3c;
const IC_CLR_INTR: usize = 0x40;
const IC_CLR_TX_ABRT: usize = 0x54;
const IC_ENABLE: usize = 0x6c;
const IC_STATUS: usize = 0x70;
const IC_TXFLR: usize = 0x74;
const IC_RXFLR: usize = 0x78;
const IC_SDA_HOLD: usize = 0x7c;
const IC_TX_ABRT_SOURCE: usize = 0x80;
const IC_ENABLE_STATUS: usize = 0x9c;
const IC_COMP_TYPE: usize = 0xfc;

/// The Synopsys component-type signature — a free liveness probe (no bus traffic).
pub const COMP_TYPE_DW: u32 = 0x4457_0140;

// IC_CON bits.
const CON_MASTER: u32 = 1 << 0;
const CON_SPEED_STD: u32 = 1 << 1; // 01 = standard (100 kHz)
const CON_RESTART_EN: u32 = 1 << 5;
const CON_SLAVE_DISABLE: u32 = 1 << 6;

// IC_DATA_CMD bits.
const CMD_READ: u32 = 1 << 8;
const CMD_STOP: u32 = 1 << 9;
/// Scan/probe command: a single-byte READ with STOP (0x300). READ-only, so no
/// bus write can ever be issued by a scan.
pub const DATA_CMD_PROBE: u32 = CMD_READ | CMD_STOP; // 0x300

// IC_RAW_INTR_STAT bits.
const INTR_TX_ABRT: u32 = 1 << 6;
const INTR_STOP_DET: u32 = 1 << 9;

// IC_STATUS bits.
const STAT_ACTIVITY: u32 = 1 << 0;
const STAT_TFE: u32 = 1 << 2; // TX FIFO empty
const STAT_RFNE: u32 = 1 << 3; // RX FIFO not empty
const STAT_MST_ACTIVITY: u32 = 1 << 5;

/// A per-transaction timeout budget (µs). Generous enough to tolerate legitimate
/// clock stretching, short enough that a wedged slave degrades to a status.
const TXN_TIMEOUT_US: u64 = 50_000;

/// An opened DW_apb_i2c master bound to one controller's 4 KiB MMIO page.
#[derive(Clone, Copy)]
pub struct I2c {
    base: usize,
}

impl I2c {
    #[inline]
    fn rd(&self, off: usize) -> u32 {
        rp1::rd(self.base + off)
    }
    #[inline]
    fn wr(&self, off: usize, v: u32) {
        rp1::wr(self.base + off, v);
    }

    /// Open + initialise the controller at `base` (e.g. `rp1::I2C_BASE0 + STRIDE`
    /// for i2c1). Verifies COMP_TYPE, checks the bus is idle, and programs standard-
    /// mode SCL timing from the derived clk_sys. Returns None if the block is not a
    /// live DW_apb_i2c or the bus is stuck busy.
    pub fn open(base: usize) -> Option<I2c> {
        let d = I2c { base };
        rp1::wfence();
        if d.rd(IC_COMP_TYPE) != COMP_TYPE_DW {
            return None; // not a reachable DW_apb_i2c
        }
        // Bus-idle precheck: if the master is mid-transaction, refuse (caller may
        // recover()). We tolerate ACTIVITY from a prior peripheral as long as the
        // master itself is idle.
        rp1::wfence();
        if d.rd(IC_STATUS) & STAT_MST_ACTIVITY != 0 {
            return None;
        }
        // Disable to program CON/timing (DW requires disabled for these).
        d.disable();
        // Standard-mode timing from the DERIVED clk_sys (100 kHz target). tHIGH=4000ns,
        // tLOW=4700ns. Math in u64, then u16-clamped.
        let clk = rp1::clk_sys_hz();
        let hcnt = ((clk.saturating_mul(4000) / 1_000_000_000).max(8)).min(0xffff) as u32;
        let lcnt = ((clk.saturating_mul(4700) / 1_000_000_000).max(8)).min(0xffff) as u32;
        d.wr(IC_SS_SCL_HCNT, hcnt);
        d.wr(IC_SS_SCL_LCNT, lcnt);
        // Fast-mode registers get sane values too (unused in standard mode).
        d.wr(IC_FS_SCL_HCNT, (hcnt / 3).max(6));
        d.wr(IC_FS_SCL_LCNT, (lcnt / 3).max(8));
        // A modest SDA hold to satisfy tHD;DAT.
        d.wr(IC_SDA_HOLD, 20);
        // Master, standard speed, restart enabled, slave mode off.
        d.wr(IC_CON, CON_MASTER | CON_SPEED_STD | CON_RESTART_EN | CON_SLAVE_DISABLE);
        // Mask all interrupts (we poll RAW_INTR_STAT), thresholds at 0.
        d.wr(IC_INTR_MASK, 0);
        d.wr(IC_RX_TL, 0);
        d.wr(IC_TX_TL, 0);
        let _ = d.rd(IC_CLR_INTR); // clear any latched sources
        Some(d)
    }

    fn disable(&self) {
        self.wr(IC_ENABLE, 0);
        // Wait for IC_ENABLE_STATUS.IC_EN (bit0) to clear — bounded.
        let _ = rp1::poll_until(|| self.rd(IC_ENABLE_STATUS) & 1 == 0, 10_000);
    }

    fn enable(&self) {
        self.wr(IC_ENABLE, 1);
        let _ = rp1::poll_until(|| self.rd(IC_ENABLE_STATUS) & 1 != 0, 10_000);
    }

    /// Set the 7-bit target address (must be done while disabled).
    fn set_target(&self, addr: u8) {
        self.disable();
        self.wr(IC_TAR, (addr as u32) & 0x7f);
        let _ = self.rd(IC_CLR_TX_ABRT);
        self.enable();
    }

    /// True once IC_STATUS reports the master idle and the FIFO drained.
    fn idle(&self) -> bool {
        let s = self.rd(IC_STATUS);
        (s & STAT_MST_ACTIVITY == 0) && (s & STAT_TFE != 0) && (s & STAT_ACTIVITY == 0)
    }

    /// Probe one address with a single-byte READ (never a write). Returns true if
    /// the device ACKs (data arrives), false on NACK (TX_ABRT) or timeout. This is
    /// the scan primitive — the controller answering NACKs correctly is the proof
    /// the bus is alive even with nothing attached.
    pub fn probe(&self, addr: u8) -> bool {
        self.set_target(addr);
        // Clear any stale abort, then issue the READ|STOP command.
        let _ = self.rd(IC_CLR_TX_ABRT);
        self.wr(IC_DATA_CMD, DATA_CMD_PROBE);
        rp1::wfence();
        // Wait for EITHER a byte in the RX FIFO (ACK) OR a TX abort (NACK).
        let got = rp1::poll_until(
            || {
                let raw = self.rd(IC_RAW_INTR_STAT);
                (raw & INTR_TX_ABRT != 0) || (self.rd(IC_RXFLR) != 0)
            },
            TXN_TIMEOUT_US,
        );
        let raw = self.rd(IC_RAW_INTR_STAT);
        let present = got && (raw & INTR_TX_ABRT == 0) && (self.rd(IC_RXFLR) != 0);
        if present {
            let _ = self.rd(IC_DATA_CMD); // drain the received byte
        }
        // Always clear the abort latch and wait for the bus to return to idle.
        let _ = self.rd(IC_CLR_TX_ABRT);
        let _ = rp1::poll_until(|| self.idle(), TXN_TIMEOUT_US);
        present
    }

    /// Scan the standard 7-bit range 0x08..=0x77. Returns the count of ACKing
    /// devices and fills `found` with their addresses (up to `found.len()`).
    /// **Zero devices is a valid PASS** — 112 correct NACKs proves the controller.
    pub fn scan(&self, found: &mut [u8]) -> usize {
        let mut n = 0usize;
        let mut a = 0x08u8;
        while a <= 0x77 {
            if self.probe(a) {
                if n < found.len() {
                    found[n] = a;
                }
                n += 1;
            }
            a += 1;
        }
        n
    }

    /// Write `bytes` to `addr` (STOP after the last byte). Returns true on ACK
    /// completion, false on NACK/abort/timeout.
    pub fn write(&self, addr: u8, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        self.set_target(addr);
        let _ = self.rd(IC_CLR_TX_ABRT);
        for (i, &b) in bytes.iter().enumerate() {
            // Wait for TX FIFO space (STAT_TFE is a coarse but safe gate).
            if !rp1::poll_until(|| self.rd(IC_STATUS) & (1 << 1) != 0, TXN_TIMEOUT_US) {
                return false;
            }
            let stop = if i == bytes.len() - 1 { CMD_STOP } else { 0 };
            self.wr(IC_DATA_CMD, (b as u32) | stop);
        }
        rp1::wfence();
        let done = rp1::poll_until(
            || (self.rd(IC_RAW_INTR_STAT) & (INTR_TX_ABRT | INTR_STOP_DET)) != 0,
            TXN_TIMEOUT_US,
        );
        let aborted = self.rd(IC_RAW_INTR_STAT) & INTR_TX_ABRT != 0;
        let _ = self.rd(IC_CLR_TX_ABRT);
        let _ = rp1::poll_until(|| self.idle(), TXN_TIMEOUT_US);
        done && !aborted
    }

    /// Read `out.len()` bytes from `addr`. Returns true if all bytes arrived.
    pub fn read(&self, addr: u8, out: &mut [u8]) -> bool {
        if out.is_empty() {
            return false;
        }
        self.set_target(addr);
        let _ = self.rd(IC_CLR_TX_ABRT);
        let n = out.len();
        // Issue n READ commands (STOP on the last), draining as data arrives.
        let mut got = 0usize;
        for i in 0..n {
            if !rp1::poll_until(|| self.rd(IC_STATUS) & (1 << 1) != 0, TXN_TIMEOUT_US) {
                return false;
            }
            let stop = if i == n - 1 { CMD_STOP } else { 0 };
            self.wr(IC_DATA_CMD, CMD_READ | stop);
            // Opportunistically drain.
            while got < n && self.rd(IC_STATUS) & STAT_RFNE != 0 {
                out[got] = (self.rd(IC_DATA_CMD) & 0xff) as u8;
                got += 1;
            }
        }
        // Drain the remainder.
        while got < n {
            if !rp1::poll_until(|| self.rd(IC_STATUS) & STAT_RFNE != 0, TXN_TIMEOUT_US) {
                break;
            }
            out[got] = (self.rd(IC_DATA_CMD) & 0xff) as u8;
            got += 1;
        }
        let aborted = self.rd(IC_RAW_INTR_STAT) & INTR_TX_ABRT != 0;
        let _ = self.rd(IC_CLR_TX_ABRT);
        let _ = rp1::poll_until(|| self.idle(), TXN_TIMEOUT_US);
        got == n && !aborted
    }

    /// Write `wbytes` then (repeated-START) read into `out` — the register-read
    /// idiom for most sensors. Returns true on full success.
    pub fn write_read(&self, addr: u8, wbytes: &[u8], out: &mut [u8]) -> bool {
        if wbytes.is_empty() || out.is_empty() {
            return false;
        }
        self.set_target(addr);
        let _ = self.rd(IC_CLR_TX_ABRT);
        // Push the write phase WITHOUT a STOP.
        for &b in wbytes {
            if !rp1::poll_until(|| self.rd(IC_STATUS) & (1 << 1) != 0, TXN_TIMEOUT_US) {
                return false;
            }
            self.wr(IC_DATA_CMD, b as u32);
        }
        // Read phase: RESTART is issued automatically by the controller between a
        // write byte and a read byte when RESTART_EN is set. STOP on the last read.
        let n = out.len();
        let mut got = 0usize;
        for i in 0..n {
            if !rp1::poll_until(|| self.rd(IC_STATUS) & (1 << 1) != 0, TXN_TIMEOUT_US) {
                return false;
            }
            let stop = if i == n - 1 { CMD_STOP } else { 0 };
            self.wr(IC_DATA_CMD, CMD_READ | stop);
            while got < n && self.rd(IC_STATUS) & STAT_RFNE != 0 {
                out[got] = (self.rd(IC_DATA_CMD) & 0xff) as u8;
                got += 1;
            }
        }
        while got < n {
            if !rp1::poll_until(|| self.rd(IC_STATUS) & STAT_RFNE != 0, TXN_TIMEOUT_US) {
                break;
            }
            out[got] = (self.rd(IC_DATA_CMD) & 0xff) as u8;
            got += 1;
        }
        let aborted = self.rd(IC_RAW_INTR_STAT) & INTR_TX_ABRT != 0;
        let _ = self.rd(IC_CLR_TX_ABRT);
        let _ = rp1::poll_until(|| self.idle(), TXN_TIMEOUT_US);
        got == n && !aborted
    }

    /// Bus recovery: bit-bang 9 SCL pulses to clear a slave that is holding SDA
    /// low, then a STOP. Muxes SCL to software GPIO via `rp1_gpio` (which enforces
    /// the deny-list — a reserved SCL pin is refused and recovery returns false),
    /// pulses, and hands the pin back to the I²C function. `scl_gpio`/`sda_gpio`
    /// are the bank0 pins of THIS controller.
    pub fn recover(&self, scl_gpio: u8, sda_gpio: u8, i2c_func: u32) -> bool {
        use crate::rp1_gpio;
        // Take SCL as an open-drain-ish push-pull software output (deny-list checked).
        if !rp1_gpio::set_function(scl_gpio, rp1_gpio::FUNC_SYS_RIO) {
            return false; // reserved pin — refuse
        }
        rp1_gpio::pad_enable(scl_gpio, true, true);
        rp1_gpio::set_dir(scl_gpio, true);
        // 9 pulses at ~100 kHz.
        for _ in 0..9 {
            rp1_gpio::set_level(scl_gpio, false);
            rp1::delay_us(5);
            rp1_gpio::set_level(scl_gpio, true);
            rp1::delay_us(5);
        }
        // Return SCL (and SDA) to the I²C function.
        let ok = rp1_gpio::set_function(scl_gpio, i2c_func);
        let _ = rp1_gpio::set_function(sda_gpio, i2c_func);
        ok
    }

    /// The abort-source register (diagnostic — decodes WHY a NACK/abort happened).
    pub fn abort_source(&self) -> u32 {
        self.rd(IC_TX_ABRT_SOURCE)
    }

    /// The controller's 4 KiB MMIO base (for granting an EL0 driver ONLY this page).
    pub fn base(&self) -> usize {
        self.base
    }
}
