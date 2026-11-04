#![no_std]
//! HookProbe HAL — the strict hardware-abstraction boundary.
//!
//! The `kernel` crate depends ONLY on these traits and contains NO
//! `cfg(target_arch)`. Each arch crate (`arch-aarch64`, later `arch-x86_64`)
//! implements them. Porting = implementing this trait set, not editing `kernel`.

/// A byte-oriented debug console (early UART, etc.).
pub trait Console {
    /// Emit one byte to the console.
    fn putc(&self, byte: u8);

    /// Emit a string (translating `\n` to CRLF for serial terminals).
    fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                self.putc(b'\r');
            }
            self.putc(b);
        }
    }
}

/// An interrupt controller (GICv2/v3 on aarch64, APIC on x86).
pub trait IrqController {
    /// Bring the controller up (distributor + CPU interface).
    fn init(&self);
    /// Route + unmask a specific interrupt id.
    fn enable(&self, intid: u32);
    /// Acknowledge the pending interrupt; returns its id.
    fn ack(&self) -> u32;
    /// Signal end-of-interrupt for `intid`.
    fn eoi(&self, intid: u32);
}

/// A periodic tick source for the scheduler (ARM generic timer / HPET).
pub trait Timer {
    /// Start a periodic interrupt at `hz` ticks per second.
    fn start(&self, hz: u32);
    /// Re-arm for the next period (called from the timer IRQ handler).
    fn rearm(&self);
}

/// The MMU + physical frame allocator (aarch64 stage-1, x86 CR3 paging later).
pub trait Mmu {
    /// Build the identity map + init the physical frame allocator. MMU still off.
    fn init(&self);
    /// Turn the MMU on (aarch64: SCTLR_EL1.M/C/I). Safe under an identity map.
    fn enable(&self);
    /// Is translation currently on?
    fn enabled(&self) -> bool;
    /// Allocate one zeroed physical frame; 0 = out of memory.
    fn alloc_frame(&self) -> usize;
    /// Map one 4 KiB page `va -> pa` (`device` selects MMIO vs normal memory).
    fn map_page(&self, va: usize, pa: usize, device: bool) -> bool;
}

/// Error from a block-device operation (P15 sealed storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockErr {
    /// LBA is outside the device (>= block_count).
    OutOfRange,
    /// The transfer did not complete (SDHCI error / timeout).
    Io,
    /// The device is not initialised / not present.
    NotReady,
    /// A write was refused (read-only build, or a write-window guard rejected it).
    WriteRefused,
}

/// A 512-byte-sector block device (P15). The read path is always available; the
/// write path is compiled out by default (`p15-write`) and, where present, is
/// additionally bounded by an independent LBA guard — LBA 0 and any partition
/// sector are never writable. All blocks are exactly 512 bytes.
pub trait BlockDev {
    /// Number of 512-byte sectors on the device.
    fn block_count(&self) -> u64;
    /// Read one 512-byte sector at `lba` into `buf`.
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr>;
    /// Write one 512-byte sector at `lba`. Default: refuse (read-only). An arch
    /// driver only overrides this behind its own `p15-write` feature.
    fn write_block(&mut self, _lba: u64, _buf: &[u8; 512]) -> Result<(), BlockErr> {
        Err(BlockErr::WriteRefused)
    }
}

// Still to come alongside their phase (the boundary exists from commit one):
//   P3:  syscall entry


// ── A/B commit content rule (shared by the CM5 eMMC driver's Gate 1 and the QEMU self-test) ──
const SLOT_KEY: &[u8; 13] = b"kernel=heqk8-";

/// Offset of the slot letter of the ONE uncommented `kernel=heqk8-[ab].img` line in a sector
/// (start of sector or right after a newline), or None if there is none or more than one.
pub fn slot_line_letter(sec: &[u8; 512]) -> Option<usize> {
    let mut found = None;
    let mut o = 0usize;
    while o + SLOT_KEY.len() + 5 <= 512 {
        if &sec[o..o + SLOT_KEY.len()] == SLOT_KEY
            && (o == 0 || sec[o - 1] == b'\n')
            && matches!(sec[o + 13], b'a' | b'b')
            && &sec[o + 14..o + 18] == b".img"
        {
            if found.is_some() {
                return None;
            }
            found = Some(o + 13);
        }
        o += 1;
    }
    found
}

/// The A/B-commit content rule: `new` equals `cur` except for exactly ONE byte, and that byte is
/// the slot letter of `cur`'s single `kernel=heqk8-?.img` line, flipped a<->b.
pub fn is_slot_letter_flip(cur: &[u8; 512], new: &[u8; 512]) -> bool {
    let Some(p) = slot_line_letter(cur) else { return false };
    let mut diffs = 0usize;
    for k in 0..512 {
        if cur[k] != new[k] {
            diffs += 1;
            if k != p {
                return false;
            }
        }
    }
    diffs == 1 && matches!((cur[p], new[p]), (b'a', b'b') | (b'b', b'a'))
}
