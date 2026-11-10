//! Crash record (production phase 3): why did the last boot end?
//!
//! A kernel panic or an unexpected EL1 fault resets the unit through the EL2 gate (`hvc #0`), and the
//! runtime watchdog resets a hung one. `last_reset` (HBoot's PM_RSTS flag) says *that* it happened; this
//! record says *why*: the panic message or the fault registers, written into one reserved DRAM page just
//! before the reset and cleaned to the point of coherency (a warm reset does not run the caches' write-back).
//! The next boot takes it once (and clears it), prints it on the console and serves it in `/api/health`.
//!
//! Best effort by design: DRAM keeps its contents across the PM watchdog's warm reset on the boards we
//! measured, but a power cut loses it — that is fine, a power cut is not a crash. The record is checksummed,
//! so stale or random memory never reads as a crash.
//!
//! CM5: the 64 KiB page at 0x3FF9_0000 — directly below HBoot's handoff pages (0x3FFA_0000..0x4000_0000),
//! outside the kernel image, the page-table pool and the JIT pool. QEMU: a static buffer (the self-test
//! exercises the format; QEMU itself exits on a panic).

use core::fmt::{self, Write};

const MAGIC: u64 = 0x3143_4552_4b51_4548; // "HEQKREC1"
/// Message bytes kept (a panic message + location fits comfortably).
pub const MSG: usize = 400;

#[repr(C)]
struct Rec {
    magic: u64,
    /// 1 = panic, 2 = unexpected kernel fault
    kind: u32,
    len: u32,
    esr: u64,
    elr: u64,
    far: u64,
    sum: u64,
    msg: [u8; MSG],
}

#[cfg(feature = "cm5")]
const REC_PA: usize = 0x3FF9_0000;

#[cfg(not(feature = "cm5"))]
static mut QEMU_REC: Rec = Rec { magic: 0, kind: 0, len: 0, esr: 0, elr: 0, far: 0, sum: 0, msg: [0; MSG] };

fn rec() -> *mut Rec {
    #[cfg(feature = "cm5")]
    {
        REC_PA as *mut Rec
    }
    #[cfg(not(feature = "cm5"))]
    {
        unsafe { core::ptr::addr_of_mut!(QEMU_REC) }
    }
}

fn checksum(kind: u32, len: u32, esr: u64, elr: u64, far: u64, msg: &[u8]) -> u64 {
    // FNV-1a over the fields: a corruption detector, not a security boundary (the reader only prints it)
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: u8| {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    for b in kind.to_le_bytes().iter().chain(len.to_le_bytes().iter()) {
        eat(*b);
    }
    for v in [esr, elr, far] {
        for b in v.to_le_bytes() {
            eat(b);
        }
    }
    for &b in msg {
        eat(b);
    }
    h
}

/// Clean the record's cache lines to the point of coherency (a reset does not write dirty lines back).
fn clean() {
    let base = rec() as usize;
    let end = base + core::mem::size_of::<Rec>();
    let mut a = base & !63;
    while a < end {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) a, options(nostack)) };
        a += 64;
    }
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

struct Buf {
    b: [u8; MSG],
    n: usize,
}
impl Write for Buf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &c in s.as_bytes() {
            if self.n < MSG {
                // keep it one printable, JSON-safe line
                self.b[self.n] = if (0x20..0x7f).contains(&c) && c != b'"' && c != b'\\' { c } else { b' ' };
                self.n += 1;
            }
        }
        Ok(())
    }
}

/// Write the record (panic/fault path: no allocation, no locks; called with interrupts masked).
pub fn write(kind: u32, esr: u64, elr: u64, far: u64, msg: fmt::Arguments) {
    let mut b = Buf { b: [0; MSG], n: 0 };
    let _ = b.write_fmt(msg);
    let sum = checksum(kind, b.n as u32, esr, elr, far, &b.b[..b.n]);
    unsafe {
        let r = rec();
        core::ptr::write_volatile(r, Rec { magic: MAGIC, kind, len: b.n as u32, esr, elr, far, sum, msg: b.b });
    }
    clean();
}

/// What the previous boot left behind.
#[derive(Clone, Copy)]
pub struct Crash {
    pub kind: u32,
    pub esr: u64,
    pub elr: u64,
    pub far: u64,
    pub len: usize,
    pub msg: [u8; MSG],
}
impl Crash {
    pub fn kind_name(&self) -> &'static str {
        if self.kind == 1 { "panic" } else { "kernel fault" }
    }
    pub fn text(&self) -> &str {
        core::str::from_utf8(&self.msg[..self.len]).unwrap_or("")
    }
}

/// Take the record once: a valid one is returned and cleared (a later reset for another reason is never
/// blamed on an old crash); anything else (power-on garbage, a torn write) reads as None.
pub fn take() -> Option<Crash> {
    let r = unsafe { core::ptr::read_volatile(rec()) };
    let valid = r.magic == MAGIC
        && (r.kind == 1 || r.kind == 2)
        && (r.len as usize) <= MSG
        && r.sum == checksum(r.kind, r.len, r.esr, r.elr, r.far, &r.msg[..r.len as usize]);
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec()).magic), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec()).sum), 0);
    }
    clean();
    valid.then_some(Crash { kind: r.kind, esr: r.esr, elr: r.elr, far: r.far, len: r.len as usize, msg: r.msg })
}

/// `[P-crashrec]` — the format: a written record is taken once with its message, a second take is empty,
/// a flipped byte or random memory never reads as a crash, quotes/control bytes are made JSON-safe.
pub fn selftest() -> bool {
    write(1, 0, 0, 0, format_args!("panicked at kernel/src/x.rs:1:2: \"boom\"\n"));
    let a = take();
    let first = a.is_some_and(|c| c.kind == 1 && c.text() == "panicked at kernel/src/x.rs:1:2:  boom  ");
    let second = take().is_none();
    write(2, 0x9600_0045, 0xffff_0000_1234, 0xdead, format_args!("Sync/SPx"));
    unsafe { (*rec()).msg[0] ^= 1 };
    let corrupt = take().is_none();
    write(2, 0x9600_0045, 0x1234, 0xdead, format_args!("Sync/SPx"));
    let fault = take().is_some_and(|c| c.kind == 2 && c.esr == 0x9600_0045 && c.far == 0xdead && c.text() == "Sync/SPx");
    unsafe { (*rec()).magic = MAGIC }; // magic alone (stale memory) is not a record
    let stale = take().is_none();
    first && second && corrupt && fault && stale
}
