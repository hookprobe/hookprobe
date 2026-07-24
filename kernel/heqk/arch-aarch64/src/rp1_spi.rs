//! P13 — RP1 SPI master (Synopsys DW_apb_ssi), CM5 / BCM2712.
//!
//! Strictly PIO; the DMACR register is NEVER written (no DMA — the 32-entry FIFO
//! is ample). `open()` rejects the slave-only instances (spi4 / spi7), probes the
//! VERSION id, and auto-detects the FIFO depth. `selftest_loopback()` uses the
//! controller's internal shift-register loop (CTRLR0.SRL) with the pads left
//! UNMUXED (FUNCSEL=NULL) so NOTHING appears on the 40-pin header.
//!
//! Every wait is bounded via `rp1::poll_until`.

use crate::rp1;

// --- DW_apb_ssi register offsets ----------------------------------------------
const CTRLR0: usize = 0x00;
const CTRLR1: usize = 0x04;
const SSIENR: usize = 0x08;
const SER: usize = 0x10; // slave-enable (chip-select) register
const BAUDR: usize = 0x14;
const TXFTLR: usize = 0x18;
const RXFTLR: usize = 0x1c;
const TXFLR: usize = 0x20;
const RXFLR: usize = 0x24;
const SR: usize = 0x28; // status register
const IMR: usize = 0x2c;
const ICR: usize = 0x48; // interrupt clear
const DR: usize = 0x60; // data register
const SSI_VERSION_ID: usize = 0x5c;

// CTRLR0 bits (DW_apb_ssi, 32-bit CTRLR0 variant).
const CTRLR0_DFS_8BIT: u32 = 0x7; // data frame size - 1 (8-bit)
const CTRLR0_TMOD_TXRX: u32 = 0b00 << 8; // transmit & receive
const CTRLR0_SRL: u32 = 1 << 11; // shift-register loop = internal loopback

// SR bits.
const SR_BUSY: u32 = 1 << 0;
const SR_TFNF: u32 = 1 << 1; // TX FIFO not full
const SR_TFE: u32 = 1 << 2; // TX FIFO empty
const SR_RFNE: u32 = 1 << 3; // RX FIFO not empty

const XFER_TIMEOUT_US: u64 = 20_000;

/// An opened DW_apb_ssi master bound to one controller's 4 KiB MMIO page.
#[derive(Clone, Copy)]
pub struct Spi {
    base: usize,
    fifo_depth: u32,
}

impl Spi {
    #[inline]
    fn rd(&self, off: usize) -> u32 {
        rp1::rd(self.base + off)
    }
    #[inline]
    fn wr(&self, off: usize, v: u32) {
        rp1::wr(self.base + off, v);
    }

    fn disable(&self) {
        self.wr(SSIENR, 0);
    }
    fn enable(&self) {
        self.wr(SSIENR, 1);
    }

    /// Open the controller at `base`. Rejects the RP1 slave-only instances
    /// (spi4, spi7), reads the VERSION id, and auto-detects the FIFO depth by
    /// probing TXFTLR. Returns None if the instance is refused or the block looks
    /// unreachable.
    pub fn open(base: usize) -> Option<Spi> {
        // Which spiN is this? Refuse the slave-only instances 4 and 7.
        if base >= rp1::SPI_BASE0 {
            let inst = (base - rp1::SPI_BASE0) / rp1::SPI_STRIDE;
            if inst == 4 || inst == 7 {
                return None; // slave-only instance — not a usable master
            }
        }
        let mut d = Spi { base, fifo_depth: 0 };
        d.disable();
        rp1::wfence();
        // VERSION probe — a DW_apb_ssi returns an ASCII-ish version word ("3.x").
        let ver = d.rd(SSI_VERSION_ID);
        if ver == 0 || ver == 0xFFFF_FFFF {
            return None; // block not reachable / not present
        }
        // FIFO depth auto-detect: write ascending thresholds to TXFTLR; the field
        // saturates at (depth-1). DW FIFOs are 8..256 deep.
        d.wr(TXFTLR, 0xff);
        let max = d.rd(TXFTLR) & 0xff;
        d.wr(TXFTLR, 0);
        d.fifo_depth = max + 1;
        if d.fifo_depth < 2 {
            d.fifo_depth = 32; // conservative fallback
        }
        // Mask interrupts (we poll SR), clear latches.
        d.wr(IMR, 0);
        let _ = d.rd(ICR);
        d.wr(SER, 0); // no chip-select asserted yet
        Some(d)
    }

    /// Detected FIFO depth (entries).
    pub fn fifo_depth(&self) -> u32 {
        self.fifo_depth
    }

    /// Assert/deassert a chip-select line (SER bit `cs`). PIO-only; the caller is
    /// responsible for muxing the corresponding CSn pad (via rp1_gpio) if it wants
    /// the CS to appear on the header. Leaving SER=0 keeps all CS lines idle.
    pub fn set_cs(&self, cs: u8, on: bool) {
        let bit = 1u32 << cs;
        let cur = self.rd(SER);
        self.wr(SER, if on { cur | bit } else { cur & !bit });
    }

    fn config_8bit(&self, extra_ctrlr0: u32) {
        self.disable();
        self.wr(CTRLR0, CTRLR0_DFS_8BIT | CTRLR0_TMOD_TXRX | extra_ctrlr0);
        self.wr(CTRLR1, 0);
        // A safe mid divider off clk_sys (BAUDR must be even, >=2). ~1 MHz-ish.
        let baud = ((rp1::clk_sys_hz() / 1_000_000) & !1).max(2).min(0xfffe) as u32;
        self.wr(BAUDR, baud);
        self.wr(TXFTLR, 0);
        self.wr(RXFTLR, 0);
    }

    /// Full-duplex 8-bit transfer: clock out `tx`, capture `rx` (same length).
    /// `rx` may be shorter than `tx`; extra received bytes are dropped. Returns
    /// true if the transfer completed within the bound.
    pub fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> bool {
        if tx.is_empty() {
            return false;
        }
        self.config_8bit(0);
        self.enable();
        let n = tx.len();
        let mut sent = 0usize;
        let mut got = 0usize;
        while got < n {
            // Fill TX FIFO while there's space and data.
            while sent < n && self.rd(SR) & SR_TFNF != 0 {
                self.wr(DR, tx[sent] as u32);
                sent += 1;
            }
            // Drain RX FIFO.
            while self.rd(SR) & SR_RFNE != 0 {
                let b = (self.rd(DR) & 0xff) as u8;
                if got < rx.len() {
                    rx[got] = b;
                }
                got += 1;
                if got >= n {
                    break;
                }
            }
            if got < n
                && !rp1::poll_until(
                    || self.rd(SR) & (SR_RFNE | SR_TFNF) != 0,
                    XFER_TIMEOUT_US,
                )
            {
                self.disable();
                return false;
            }
        }
        let _ = rp1::poll_until(|| self.rd(SR) & SR_BUSY == 0, XFER_TIMEOUT_US);
        self.disable();
        true
    }

    /// Write-only convenience (received bytes discarded).
    pub fn write(&self, tx: &[u8]) -> bool {
        let mut sink = [0u8; 1];
        // transfer() tolerates a short rx buffer.
        self.transfer(tx, &mut sink)
    }

    /// Read-only convenience: clock out zeros, capture `out.len()` bytes.
    pub fn read(&self, out: &mut [u8]) -> bool {
        let n = out.len();
        if n == 0 {
            return false;
        }
        self.config_8bit(0);
        self.enable();
        let mut sent = 0usize;
        let mut got = 0usize;
        while got < n {
            while sent < n && self.rd(SR) & SR_TFNF != 0 {
                self.wr(DR, 0);
                sent += 1;
            }
            while got < n && self.rd(SR) & SR_RFNE != 0 {
                out[got] = (self.rd(DR) & 0xff) as u8;
                got += 1;
            }
            if got < n && !rp1::poll_until(|| self.rd(SR) & SR_RFNE != 0, XFER_TIMEOUT_US) {
                self.disable();
                return false;
            }
        }
        let _ = rp1::poll_until(|| self.rd(SR) & SR_BUSY == 0, XFER_TIMEOUT_US);
        self.disable();
        true
    }

    /// Internal-loopback self-test: enable CTRLR0.SRL (the shift register feeds its
    /// own output back to its input) and verify a byte pattern round-trips. The
    /// pads are left at FUNCSEL=NULL (unmuxed) so NOTHING is driven on the header —
    /// this proves the controller + FIFOs without touching any external pin.
    /// Returns true iff every byte read back matches.
    pub fn selftest_loopback(&self) -> bool {
        const PAT: [u8; 4] = [0xA5, 0x5A, 0x00, 0xFF];
        self.config_8bit(CTRLR0_SRL);
        self.wr(SER, 0); // no external CS — purely internal
        self.enable();
        let mut ok = true;
        let mut got = [0u8; 4];
        let mut sent = 0usize;
        let mut rcv = 0usize;
        let n = PAT.len();
        while rcv < n {
            while sent < n && self.rd(SR) & SR_TFNF != 0 {
                self.wr(DR, PAT[sent] as u32);
                sent += 1;
            }
            while rcv < n && self.rd(SR) & SR_RFNE != 0 {
                got[rcv] = (self.rd(DR) & 0xff) as u8;
                rcv += 1;
            }
            if rcv < n && !rp1::poll_until(|| self.rd(SR) & SR_RFNE != 0, XFER_TIMEOUT_US) {
                ok = false;
                break;
            }
        }
        let _ = rp1::poll_until(|| self.rd(SR) & SR_BUSY == 0, XFER_TIMEOUT_US);
        self.disable();
        ok && got == PAT
    }

    /// VERSION id word (diagnostic).
    pub fn version(&self) -> u32 {
        self.rd(SSI_VERSION_ID)
    }

    /// (TXFLR, RXFLR) FIFO occupancy — diagnostic.
    pub fn fifo_levels(&self) -> (u32, u32) {
        (self.rd(TXFLR), self.rd(RXFLR))
    }

    /// The controller's 4 KiB MMIO base.
    pub fn base(&self) -> usize {
        self.base
    }
}
