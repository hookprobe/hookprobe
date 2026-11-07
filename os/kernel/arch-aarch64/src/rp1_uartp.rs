//! P13 — RP1 peripheral UART (PL011), CM5 / BCM2712.
//!
//! These are the *peripheral* UARTs (uart1..5) a sensor/actuator might use — NOT
//! the console. `open()` REJECTS instance 0: RP1 uart0 (GPIO14/15) is the boot
//! console (uart.rs / boot_cm5.s own it), and reprogramming it makes the board go
//! dark mid-boot. This driver NEVER writes the RP1 CLK_UART_* clock-control
//! registers (that is firmware/console territory); it only touches the PL011's own
//! registers, and its self-test uses the PL011 internal loopback (CR.LBE) so no
//! byte reaches a header pin.
//!
//! All waits are bounded via `rp1::poll_until`.

use crate::rp1;

// PL011 register offsets (same layout uart.rs uses for the console).
const DR: usize = 0x00;
const FR: usize = 0x18;
const IBRD: usize = 0x24;
const FBRD: usize = 0x28;
const LCR_H: usize = 0x2c;
const CR: usize = 0x30;
const IMSC: usize = 0x38;
const ICR: usize = 0x44;
const UART_PERIPH_ID0: usize = 0xfe0; // PrimeCell ID0 = 0x11 for a PL011

const FR_RXFE: u32 = 1 << 4; // RX FIFO empty
const FR_TXFF: u32 = 1 << 5; // TX FIFO full
const FR_BUSY: u32 = 1 << 3;

const LCR_FEN: u32 = 1 << 4; // FIFO enable
const LCR_WLEN_8: u32 = 0b11 << 5; // 8-bit words

const CR_UARTEN: u32 = 1 << 0;
const CR_LBE: u32 = 1 << 7; // loopback enable
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

const IO_TIMEOUT_US: u64 = 20_000;

/// An opened PL011 peripheral UART (never instance 0 / the console).
#[derive(Clone, Copy)]
pub struct UartP {
    base: usize,
}

impl UartP {
    #[inline]
    fn rd(&self, off: usize) -> u32 {
        rp1::rd(self.base + off)
    }
    #[inline]
    fn wr(&self, off: usize, v: u32) {
        rp1::wr(self.base + off, v);
    }

    /// Open peripheral UART `instance` (1..=5). Instance 0 is the console and is
    /// REFUSED. Verifies the PrimeCell PL011 id, then leaves the block quiesced
    /// (disabled) for the caller to configure. Returns None if refused / absent.
    pub fn open(instance: u8) -> Option<UartP> {
        if instance == 0 {
            return None; // uart0 = the boot console — NEVER reprogram it
        }
        let base = rp1::UART_BASE0 + (instance as usize) * rp1::UART_STRIDE;
        let d = UartP { base };
        rp1::wfence();
        // PL011 PeriphID0 low byte = 0x11.
        if d.rd(UART_PERIPH_ID0) & 0xff != 0x11 {
            return None;
        }
        // Quiesce: disable, mask interrupts, clear latches. Do NOT touch clocks.
        d.wr(CR, 0);
        d.wr(IMSC, 0);
        d.wr(ICR, 0x7ff);
        Some(d)
    }

    /// Configure 8N1 with the given integer/fractional baud divisors (the caller
    /// computes them from the KNOWN clk_uart — we never program the clock itself),
    /// enable TX+RX+FIFO. Pass `loopback=true` for the internal-loopback self-test.
    pub fn configure(&self, ibrd: u32, fbrd: u32, loopback: bool) {
        self.wr(CR, 0); // must be disabled to change LCR_H/baud
        self.wr(IBRD, ibrd & 0xffff);
        self.wr(FBRD, fbrd & 0x3f);
        self.wr(LCR_H, LCR_WLEN_8 | LCR_FEN);
        let mut cr = CR_UARTEN | CR_TXE | CR_RXE;
        if loopback {
            cr |= CR_LBE;
        }
        self.wr(CR, cr);
        rp1::wfence();
    }

    /// Transmit one byte (bounded wait for TX FIFO space; drops the byte on timeout).
    pub fn putc(&self, b: u8) -> bool {
        if !rp1::poll_until(|| self.rd(FR) & FR_TXFF == 0, IO_TIMEOUT_US) {
            return false;
        }
        self.wr(DR, b as u32);
        true
    }

    /// Receive one byte (bounded wait for RX data). None on timeout.
    pub fn getc(&self) -> Option<u8> {
        if !rp1::poll_until(|| self.rd(FR) & FR_RXFE == 0, IO_TIMEOUT_US) {
            return None;
        }
        Some((self.rd(DR) & 0xff) as u8)
    }

    /// Internal-loopback self-test: enable CR.LBE, send a pattern, read it back.
    /// Nothing reaches a header pin (loopback is inside the PL011). Uses a nominal
    /// baud (IBRD/FBRD supplied) — the clock stays whatever firmware set. Returns
    /// true iff every byte round-trips.
    pub fn selftest_loopback(&self, ibrd: u32, fbrd: u32) -> bool {
        const PAT: [u8; 4] = [0x55, 0xAA, 0x00, 0xFF];
        self.configure(ibrd, fbrd, true);
        let mut ok = true;
        for &b in &PAT {
            if !self.putc(b) {
                ok = false;
                break;
            }
            // Wait for the byte to loop through, then read it.
            let _ = rp1::poll_until(|| self.rd(FR) & FR_BUSY == 0, IO_TIMEOUT_US);
            match self.getc() {
                Some(r) if r == b => {}
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        self.wr(CR, 0); // leave it disabled again
        ok
    }

    /// The controller's 4 KiB MMIO base.
    pub fn base(&self) -> usize {
        self.base
    }
}
