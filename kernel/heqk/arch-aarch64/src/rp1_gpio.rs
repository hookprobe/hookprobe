//! P13 — RP1 bank0 GPIO / pinmux (CM5 / BCM2712).
//!
//! bank0 = **GPIO0-27**, the 40-pin header. `CTRL = io_bank0 + idx*8 + 4`,
//! `PAD = pads_bank0 + 4 + idx*4`, FUNCSEL **5 = SYS_RIO** (software GPIO via the
//! RIO OUT/OE/IN registers), `0x1f` = NULL. Pad bit7 = OD (output disable),
//! bit6 = IE (input enable), bit3 = PUE (pull-up), bit2 = PDE (pull-down).
//!
//! The pin **deny-list is the load-bearing safety property** and is checked
//! BEFORE ANY MMIO WRITE in every entry point (`set_function`, `claim_gpio`,
//! `mux_group`, `set_pull`, `pad_enable`). `mux_group` validates the WHOLE slice
//! before applying, so a partial mux is impossible.
//!
//! Only bank0 is programmable here — bank1/bank2 are refused (bank1 holds
//! ETH_RST_N, driven only by the trusted GEM driver in `gem.rs`).
//!
//! The RP1 GPIO block is SEPARATE from the BCM2712 `gio` that carries WiFi's
//! WL_ON/SDIO2 — nothing here can affect the radio.

use crate::rp1::{self, IO_BANK0, PADS_BANK0, SYS_RIO0};
use core::sync::atomic::{AtomicU32, Ordering};

/// The reserved pins — remuxing/driving any of these breaks the box:
/// - **14, 15** = UART0 console (board goes dark mid-boot).
/// - **32** = ETH_RST_N (drops the GEM PHY into reset — kills the IDS datapath).
///   (32 is bank1, refused by the bank0 check too, but listed for defence-in-depth.)
/// - **37** = eth PHY IRQ, **38/39** = i2c6 CSI/DSI, **44** = PWR LED.
pub const RESERVED: &[u8] = &[14, 15, 32, 37, 38, 39, 44];

/// Highest programmable bank0 pin.
pub const BANK0_MAX: u8 = 27;

/// FUNCSEL value routing a pad to software GPIO (the RIO block).
pub const FUNC_SYS_RIO: u32 = 5;
/// FUNCSEL value that disconnects the pad (NULL).
pub const FUNC_NULL: u32 = 0x1f;

// RIO register offsets (same block gem.rs drives for ETH_RST_N).
const RIO_OUT: usize = 0x00;
const RIO_OE: usize = 0x04;
const RIO_IN: usize = 0x08;

// Pad control bits.
const PAD_PDE: u32 = 1 << 2; // pull-down enable
const PAD_PUE: u32 = 1 << 3; // pull-up enable
const PAD_IE: u32 = 1 << 6; // input enable
const PAD_OD: u32 = 1 << 7; // output disable

/// Owner-tracking bitmap: one bit per bank0 pin claimed via `claim_gpio`.
/// One owner per pin, tracked kernel-side (the datasheet has no HW arbiter).
static CLAIMED: AtomicU32 = AtomicU32::new(0);

/// Pull configuration for a pad.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pull {
    None,
    Up,
    Down,
}

/// Is `pin` on the reserved deny-list?
#[inline]
pub fn is_reserved(pin: u8) -> bool {
    let mut i = 0;
    while i < RESERVED.len() {
        if RESERVED[i] == pin {
            return true;
        }
        i += 1;
    }
    false
}

/// A bank0 pin that is NOT reserved — the precondition for every MMIO write.
#[inline]
fn writable(pin: u8) -> bool {
    pin <= BANK0_MAX && !is_reserved(pin)
}

#[inline]
fn ctrl_addr(pin: u8) -> usize {
    IO_BANK0 + (pin as usize) * 8 + 4
}
#[inline]
fn pad_addr(pin: u8) -> usize {
    PADS_BANK0 + 4 + (pin as usize) * 4
}

/// Claim ownership of a bank0 pin. Fails (returns false) for reserved pins,
/// out-of-bank pins, or a pin already claimed. Checked BEFORE any state change.
pub fn claim_gpio(pin: u8) -> bool {
    if !writable(pin) {
        return false;
    }
    let bit = 1u32 << pin;
    // CAS-free single-core kernel, but keep it atomic for defensiveness.
    let prev = CLAIMED.fetch_or(bit, Ordering::AcqRel);
    prev & bit == 0
}

/// Release a previously-claimed pin (leaves the pad electrically as-is).
pub fn release(pin: u8) {
    if pin <= BANK0_MAX {
        CLAIMED.fetch_and(!(1u32 << pin), Ordering::AcqRel);
    }
}

/// Set a pad's FUNCSEL (pinmux). Refuses reserved / out-of-bank pins BEFORE the
/// write. Returns false if refused.
pub fn set_function(pin: u8, func: u32) -> bool {
    if !writable(pin) {
        return false;
    }
    rp1::rmw(ctrl_addr(pin), 0x1f, func & 0x1f);
    rp1::wfence();
    true
}

/// Enable/disable a pad's input and output buffers (clear/set OD, set/clear IE).
/// Refuses reserved / out-of-bank pins BEFORE the write.
pub fn pad_enable(pin: u8, output: bool, input: bool) -> bool {
    if !writable(pin) {
        return false;
    }
    let mut set = 0u32;
    let mut clr = 0u32;
    if output {
        clr |= PAD_OD;
    } else {
        set |= PAD_OD;
    }
    if input {
        set |= PAD_IE;
    } else {
        clr |= PAD_IE;
    }
    rp1::rmw(pad_addr(pin), clr, set);
    rp1::wfence();
    true
}

/// Configure a pad's pull. Refuses reserved / out-of-bank pins BEFORE the write.
pub fn set_pull(pin: u8, pull: Pull) -> bool {
    if !writable(pin) {
        return false;
    }
    let (clr, set) = match pull {
        Pull::None => (PAD_PUE | PAD_PDE, 0),
        Pull::Up => (PAD_PDE, PAD_PUE),
        Pull::Down => (PAD_PUE, PAD_PDE),
    };
    rp1::rmw(pad_addr(pin), clr, set);
    rp1::wfence();
    true
}

/// Set software-GPIO direction (output-enable) via the RIO OE register. The pad
/// must already be funcselled to SYS_RIO (5). Refuses reserved / out-of-bank pins.
pub fn set_dir(pin: u8, output: bool) -> bool {
    if !writable(pin) {
        return false;
    }
    let bit = 1u32 << pin;
    if output {
        rp1::wr(SYS_RIO0 + rp1::ATOM_SET + RIO_OE, bit);
    } else {
        rp1::wr(SYS_RIO0 + rp1::ATOM_CLR + RIO_OE, bit);
    }
    rp1::wfence();
    true
}

/// Drive a software-GPIO output level via the RIO OUT register (atomic SET/CLR).
/// Refuses reserved / out-of-bank pins BEFORE the write.
pub fn set_level(pin: u8, high: bool) -> bool {
    if !writable(pin) {
        return false;
    }
    let bit = 1u32 << pin;
    if high {
        rp1::wr(SYS_RIO0 + rp1::ATOM_SET + RIO_OUT, bit);
    } else {
        rp1::wr(SYS_RIO0 + rp1::ATOM_CLR + RIO_OUT, bit);
    }
    rp1::wfence();
    true
}

/// Read a pin's live level from the RIO IN register.
pub fn get_level(pin: u8) -> bool {
    rp1::wfence();
    let v = rp1::rd(SYS_RIO0 + RIO_IN);
    (v >> pin) & 1 != 0
}

/// Mux a whole slice of pins to `func` atomically-in-intent: VALIDATE the ENTIRE
/// slice first (every pin must be a writable bank0 pin), and only then apply — so
/// a partial mux (some pins remuxed, then a reserved pin aborts) is impossible.
/// Returns false and touches NOTHING if any pin is reserved / out of bank0.
pub fn mux_group(pins: &[u8], func: u32) -> bool {
    // Phase 1: validate the whole slice. No MMIO writes yet.
    for &p in pins {
        if !writable(p) {
            return false;
        }
    }
    // Phase 2: apply.
    for &p in pins {
        rp1::rmw(ctrl_addr(p), 0x1f, func & 0x1f);
    }
    rp1::wfence();
    true
}

/// Dump a pin's register state: (CTRL, PAD, RIO_OUT, RIO_OE, RIO_IN).
pub fn dump(pin: u8) -> (u32, u32, u32, u32, u32) {
    rp1::wfence();
    (
        rp1::rd(ctrl_addr(pin)),
        rp1::rd(pad_addr(pin)),
        rp1::rd(SYS_RIO0 + RIO_OUT),
        rp1::rd(SYS_RIO0 + RIO_OE),
        rp1::rd(SYS_RIO0 + RIO_IN),
    )
}

/// The current FUNCSEL of a pad (low 5 bits of CTRL).
pub fn funcsel(pin: u8) -> u32 {
    rp1::wfence();
    rp1::rd(ctrl_addr(pin)) & 0x1f
}
