//! P13 — RP1 peripheral-bus common layer (CM5 / BCM2712).
//!
//! HEQK reaches the RP1 southbridge through the firmware-programmed prefetchable
//! 64-bit outbound PCIe window, which lands at CPU base **`0x1C_0000_0000`** (not
//! Linux's `0x1F_..`). Every working HEQK RP1 access (uart.rs, gem.rs, boot_cm5.s)
//! already uses it. The address translation is:
//!
//! ```text
//! cpu_addr(periph) = 0x1C_0000_0000 + (rp1_addr - 0x4000_0000)
//! ```
//!
//! This module is the shared plumbing for the P13 bus drivers (rp1_gpio, rp1_i2c,
//! rp1_spi, rp1_uartp): block bases, raw MMIO with the `wfence()` (dsb sy) posted-
//! write barrier the datasheet §3.3.1.1 requires, a CNTPCT-based `delay_us` /
//! wall-clock-bounded `poll_until` (NO naked `while` ever waits on hardware), and
//! the `clk_sys` derivation (register-derived, cross-checked by the FC0 frequency
//! counter — never hard-coded).
//!
//! NOTE (safety): the WiFi control lines (WL_ON, SDIO2) are BCM2712 `gio`/pinctrl
//! at `0x10_7D5x_xxxx` — a DIFFERENT block from RP1. P13 cannot touch them.

use core::ptr::{read_volatile, write_volatile};

/// Base of the RP1 outbound PCIe window in CPU physical space.
pub const RP1_BASE: usize = 0x1C_0000_0000;
/// RP1-internal addresses start at 0x4000_0000; subtract this before adding BASE.
pub const RP1_WIN_OFF: usize = 0x4000_0000;

/// Translate an RP1-internal address (datasheet Table 2, `0x4000_xxxx`) to its
/// CPU address through the bare-metal window.
#[inline]
pub fn blk(rp1_addr: usize) -> usize {
    RP1_BASE + (rp1_addr - RP1_WIN_OFF)
}

// --- Block bases (CPU addresses; datasheet Table 2 + rp1.dtsi) ----------------
/// clocks_main — PLLs, per-clock dividers, and the FC0 frequency counter.
pub const CLOCKS: usize = 0x1C_0001_8000;
/// uart0 base; uartN = UART_BASE0 + N*UART_STRIDE.
pub const UART_BASE0: usize = 0x1C_0003_0000;
pub const UART_STRIDE: usize = 0x4000;
/// spi0 base; spiN = SPI_BASE0 + N*SPI_STRIDE.
pub const SPI_BASE0: usize = 0x1C_0005_0000;
pub const SPI_STRIDE: usize = 0x4000;
/// i2c0 base; i2cN = I2C_BASE0 + N*I2C_STRIDE. (i2c1 = 0x1C_0007_4000.)
pub const I2C_BASE0: usize = 0x1C_0007_0000;
pub const I2C_STRIDE: usize = 0x4000;
/// io_bank0 / sys_rio0 / pads_bank0 — bank0 = GPIO0-27 (the 40-pin header).
pub const IO_BANK0: usize = 0x1C_000D_0000;
pub const SYS_RIO0: usize = 0x1C_000E_0000;
pub const PADS_BANK0: usize = 0x1C_000F_0000;

// Atomic aliases exist ONLY for io_bank/sys_rio/pads (per datasheet): +0x1000 XOR,
// +0x2000 SET, +0x3000 CLR. spi/i2c/uart need plain read-modify-write.
pub const ATOM_XOR: usize = 0x1000;
pub const ATOM_SET: usize = 0x2000;
pub const ATOM_CLR: usize = 0x3000;

// --- Raw MMIO -----------------------------------------------------------------
/// Read a 32-bit RP1 register. Always `wfence()` before a read-after-write, since
/// PCIe posted writes may not have landed (datasheet §3.3.1.1).
#[inline]
pub fn rd(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}
/// Write a 32-bit RP1 register.
#[inline]
pub fn wr(addr: usize, v: u32) {
    unsafe { write_volatile(addr as *mut u32, v) };
}
/// Read-modify-write: `*addr = (*addr & !clr) | set`.
#[inline]
pub fn rmw(addr: usize, clr: u32, set: u32) {
    wfence();
    let v = rd(addr);
    wr(addr, (v & !clr) | set);
}
/// Barrier that forces prior posted PCIe writes to complete before the next read.
#[inline]
pub fn wfence() {
    unsafe { core::arch::asm!("dsb sy") };
}

// --- Timing (promoted from the one copy in cyw43.rs / rtl8111.rs) -------------
/// Read the physical counter frequency (Hz).
#[inline]
fn cntfrq() -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f
}
/// Read the physical counter.
#[inline]
fn cntpct() -> u64 {
    let c: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack)) };
    c
}

/// Accurate busy-delay via the physical counter — ALWAYS terminates.
pub fn delay_us(us: u64) {
    let freq = cntfrq();
    let start = cntpct();
    let ticks = freq.saturating_mul(us) / 1_000_000;
    loop {
        if cntpct().wrapping_sub(start) >= ticks {
            break;
        }
        core::hint::spin_loop();
    }
}

/// Poll `cond` until it returns true or `timeout_us` of WALL-CLOCK time elapses.
/// Returns true if the condition was met, false on timeout. This is the ONLY way
/// a P13 driver waits on hardware — a clock-stretching I²C slave, a dead FIFO, or
/// an unclocked block must produce a *timeout*, never a wedge.
pub fn poll_until<F: FnMut() -> bool>(mut cond: F, timeout_us: u64) -> bool {
    let freq = cntfrq();
    let start = cntpct();
    let ticks = freq.saturating_mul(timeout_us) / 1_000_000;
    loop {
        if cond() {
            return true;
        }
        if cntpct().wrapping_sub(start) >= ticks {
            return false;
        }
        core::hint::spin_loop();
    }
}

// --- clk_sys derivation -------------------------------------------------------
//
// RP1's DW_apb_i2c / DW_apb_ssi are clocked from `clk_sys` (nominally 200 MHz).
// The I²C bit-timing math (HCNT/LCNT) MUST use the real rate, so we DERIVE it —
// from pll_sys (feedback + post-dividers off the 50 MHz XOSC) and the clk_sys
// integer divider — and cross-check it against the FC0 frequency counter. FC0 is
// diagnostic (a disagreement is a WARN, never fatal); the derived value is what
// the timing math consumes. If the derivation reads back implausibly (block
// unreachable / firmware layout differs), we fall back to the 200 MHz nominal so
// timing stays in range — a defensive fallback, not a hard-code of the primary path.

/// RP1 crystal oscillator (datasheet: 50 MHz on CM5).
pub const XOSC_HZ: u64 = 50_000_000;
/// clk_sys nominal (fallback only).
pub const CLK_SYS_NOMINAL_HZ: u64 = 200_000_000;

// clocks_main register offsets (from clk-rp1.c / RP1 datasheet CLOCKS map).
const PLL_SYS_CS: usize = 0x08000; // bit31 = LOCK
const PLL_SYS_FBDIV_INT: usize = 0x08008; // integer feedback divider
const PLL_SYS_PRIM: usize = 0x08010; // [20:16]=DIV1, [14:12]=DIV2 post-dividers
const CLK_SYS_DIV_INT: usize = 0x00018; // clk_sys integer divider

// FC0 frequency counter (clocks block). Offsets per the datasheet CLOCKS map;
// best-effort on metal — used only for the WARN cross-check in Stage A.
const FC0_REF_KHZ: usize = 0x0000_001c;
const FC0_MIN_KHZ: usize = 0x0000_0020;
const FC0_MAX_KHZ: usize = 0x0000_0024;
const FC0_DELAY: usize = 0x0000_0028;
const FC0_INTERVAL: usize = 0x0000_002c;
const FC0_SRC: usize = 0x0000_0030;
const FC0_STATUS: usize = 0x0000_0034;
const FC0_RESULT: usize = 0x0000_0038;
const FC0_STATUS_DONE: u32 = 1 << 4;
// FC0 source index for clk_sys (RP1 fc0_src enum). Best-effort; metal-confirmable.
const FC0_SRC_CLK_SYS: u32 = 0x01;

fn reg_sane(v: u32) -> bool {
    v != 0 && v != 0xFFFF_FFFF
}

/// Derived `clk_sys` in Hz. Reads pll_sys (fbdiv + prim post-dividers) and the
/// clk_sys integer divider off the 50 MHz XOSC; falls back to the 200 MHz nominal
/// only if the registers read back implausibly.
pub fn clk_sys_hz() -> u64 {
    wfence();
    let fb = rd(CLOCKS + PLL_SYS_FBDIV_INT) & 0xfff;
    let prim = rd(CLOCKS + PLL_SYS_PRIM);
    let div_int = rd(CLOCKS + CLK_SYS_DIV_INT) & 0xffff;
    if !reg_sane(fb) || !reg_sane(prim) {
        return CLK_SYS_NOMINAL_HZ;
    }
    let div1 = ((prim >> 16) & 0x1f).max(1) as u64;
    let div2 = ((prim >> 12) & 0x7).max(1) as u64;
    // clk_sys divider: the RP1 dividers store the value in the upper bits
    // (integer part in [23:8] on some clocks); guard to a sane 1..=255.
    let d = if div_int == 0 { 1 } else { (div_int & 0xff).max(1) as u64 };
    let vco = XOSC_HZ.saturating_mul(fb as u64);
    let f = vco / (div1 * div2) / d;
    if (100_000_000..=300_000_000).contains(&f) {
        f
    } else {
        CLK_SYS_NOMINAL_HZ
    }
}

/// Measure clk_sys with the RP1 FC0 frequency counter and return kHz (0 on
/// timeout / no result). Diagnostic cross-check for Stage A only — never gates.
pub fn measure_clk_sys_khz() -> u32 {
    // Reference = XOSC in kHz; a wide accept window; short integration.
    wr(CLOCKS + FC0_REF_KHZ, (XOSC_HZ / 1000) as u32);
    wr(CLOCKS + FC0_MIN_KHZ, 0);
    wr(CLOCKS + FC0_MAX_KHZ, 0x7fff_ffff);
    wr(CLOCKS + FC0_DELAY, 1);
    wr(CLOCKS + FC0_INTERVAL, 8);
    wfence();
    wr(CLOCKS + FC0_SRC, FC0_SRC_CLK_SYS); // arm/start
    if !poll_until(|| rd(CLOCKS + FC0_STATUS) & FC0_STATUS_DONE != 0, 50_000) {
        wr(CLOCKS + FC0_SRC, 0); // stop
        return 0;
    }
    let result = rd(CLOCKS + FC0_RESULT);
    wr(CLOCKS + FC0_SRC, 0); // stop
    // RP1 FC0_RESULT carries kHz in the upper bits with a 5-bit fraction; take the
    // integer kHz if plausible, else the raw value, else 0.
    let khz = result >> 5;
    if (50_000..=400_000).contains(&khz) {
        khz
    } else if (50_000..=400_000).contains(&result) {
        result
    } else {
        0
    }
}

/// True if pll_sys reports LOCK (diagnostic).
pub fn pll_sys_locked() -> bool {
    wfence();
    rd(CLOCKS + PLL_SYS_CS) & (1 << 31) != 0
}
