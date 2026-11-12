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
//! CM5: 0x0800_0000 (128 MiB) — above the kernel image + .bss (~0x0218_0000), below the page-table pool
//! (0x3000_0000). Chosen by measurement: canaries at 0x0800_0000 survived three EL2-gate resets in a row while
//! 0x2000_0000, 0x3F00_0000 and the first choice 0x3FF9_0000 were overwritten by the boot firmware. QEMU: a static buffer (the self-test
//! exercises the format; QEMU itself exits on a panic).

use core::fmt::{self, Write};

const MAGIC: u64 = 0x3143_4552_4b51_4548; // "HEQKREC1"
/// Message bytes kept (a panic message + location fits comfortably).
pub const MSG: usize = 400;

#[repr(C)]
struct Rec {
    magic: u64,
    /// 1 = panic, 2 = unexpected kernel fault, 3 = self-heal reset (the kernel chose to reset: `far` = uptime s)
    kind: u32,
    len: u32,
    esr: u64,
    elr: u64,
    far: u64,
    sum: u64,
    msg: [u8; MSG],
}

#[cfg(feature = "cm5")]
const REC_PA: usize = 0x0800_0000; // metal 2026-11-10 (batch 31): DRAM here survives the EL2-gate reset; 0x3FF9_0000 / 0x2000_0000 / 0x3F00_0000 do not

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

/// DRAM-retention probe (metal 2026-11-10: the record at 0x3FF9_0000 did not survive the EL2-gate reset). On every
/// crash write a checksummed canary at a few addresses outside every region heqk / HBoot use; the next boot reports
/// which survived — that picks where the record can live (or proves it needs the eMMC).
#[cfg(feature = "cm5")]
pub const PROBES: [usize; 3] = [0x0800_1000, 0x2000_0000, 0x3F00_0000];
#[cfg(feature = "cm5")]
const CANARY: u64 = 0x5942_4f52_504b_5148; // "HQKPROBY"

#[cfg(feature = "cm5")]
fn canary_words(a: usize) -> [u64; 8] {
    let mut w = [0u64; 8];
    for (i, x) in w.iter_mut().enumerate() {
        *x = CANARY ^ (a as u64).rotate_left(i as u32 * 7) ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    w
}

#[cfg(feature = "cm5")]
fn write_canaries() {
    for &a in PROBES.iter() {
        let w = canary_words(a);
        for (i, x) in w.iter().enumerate() {
            unsafe { core::ptr::write_volatile((a as *mut u64).add(i), *x) };
        }
        unsafe { core::arch::asm!("dc civac, {}", in(reg) a, options(nostack)) };
    }
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

/// Which probe canaries survived since the last crash (bit i = PROBES[i]); clears them.
#[cfg(feature = "cm5")]
pub fn take_canaries() -> u8 {
    let mut m = 0u8;
    for (k, &a) in PROBES.iter().enumerate() {
        let w = canary_words(a);
        let ok = w.iter().enumerate().all(|(i, x)| unsafe { core::ptr::read_volatile((a as *const u64).add(i)) } == *x);
        if ok {
            m |= 1 << k;
        }
        unsafe { core::ptr::write_volatile(a as *mut u64, 0) };
        unsafe { core::arch::asm!("dc civac, {}", in(reg) a, options(nostack)) };
    }
    m
}

/// Write the record (panic/fault path: no allocation, no locks; called with interrupts masked).
pub fn write(kind: u32, esr: u64, elr: u64, far: u64, msg: fmt::Arguments) {
    let mut b = Buf { b: [0; MSG], n: 0 };
    let _ = b.write_fmt(msg);
    let sum = checksum(kind, b.n as u32, esr, elr, far, &b.b[..b.n]);
    #[cfg(feature = "cm5")]
    write_canaries();
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
        match self.kind {
            1 => "panic",
            2 => "kernel fault",
            _ => "self-heal reset",
        }
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
        && (1..=3).contains(&r.kind)
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

/// Wi-Fi recovery record (audit A7, `kernel/src/wifiheal.rs`): the recovery state that must survive the ONE
/// Wi-Fi self-heal reboot (flags: bit0 = this unit already rebooted once for Wi-Fi, bit1 = Wi-Fi degraded) and the
/// diagnostic words captured BEFORE the last recovery action (firmware hash, trap registers, SDPCM credit state,
/// counters — never a key, a passphrase or a station address). Same page as the crash record (CM5: +0x400, the
/// measured-surviving DRAM), same FNV check; written on every recovery action, taken once at boot.
pub const HEAL_WORDS: usize = 24;
const HEAL_MAGIC: u64 = 0x314c_4857_4b51_4548; // "HEQKWHL1"

#[repr(C)]
struct HealRec {
    magic: u64,
    flags: u32,
    words: [u32; HEAL_WORDS],
    sum: u64,
}

#[cfg(not(feature = "cm5"))]
static mut QEMU_HEAL: HealRec = HealRec { magic: 0, flags: 0, words: [0; HEAL_WORDS], sum: 0 };

fn heal() -> *mut HealRec {
    #[cfg(feature = "cm5")]
    {
        (REC_PA + 0x400) as *mut HealRec
    }
    #[cfg(not(feature = "cm5"))]
    {
        core::ptr::addr_of_mut!(QEMU_HEAL)
    }
}

fn heal_sum(flags: u32, w: &[u32; HEAL_WORDS]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for v in core::iter::once(flags).chain(w.iter().copied()) {
        for b in v.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

fn clean_range(base: usize, len: usize) {
    let mut a = base & !63;
    while a < base + len {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) a, options(nostack)) };
        a += 64;
    }
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

/// Write the Wi-Fi recovery record (replaces the previous one).
pub fn write_heal(flags: u32, words: &[u32; HEAL_WORDS]) {
    let sum = heal_sum(flags, words);
    unsafe { core::ptr::write_volatile(heal(), HealRec { magic: HEAL_MAGIC, flags, words: *words, sum }) };
    clean_range(heal() as usize, core::mem::size_of::<HealRec>());
}

/// Take the Wi-Fi recovery record once (cleared; power-on garbage / a torn write reads as None).
pub fn take_heal() -> Option<(u32, [u32; HEAL_WORDS])> {
    let r = unsafe { core::ptr::read_volatile(heal()) };
    let valid = r.magic == HEAL_MAGIC && r.sum == heal_sum(r.flags, &r.words);
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*heal()).magic), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*heal()).sum), 0);
    }
    clean_range(heal() as usize, core::mem::size_of::<HealRec>());
    valid.then_some((r.flags, r.words))
}

/// `[P-wifiheal]` part: the recovery record is taken once, and a flipped word / a bare magic never reads back.
pub fn heal_selftest() -> bool {
    let w = [7u32; HEAL_WORDS];
    write_heal(1, &w);
    let once = take_heal() == Some((1, w)) && take_heal().is_none();
    write_heal(2, &w);
    unsafe { (*heal()).words[3] ^= 1 };
    let torn = take_heal().is_none();
    unsafe { (*heal()).magic = HEAL_MAGIC };
    let stale = take_heal().is_none();
    once && torn && stale
}

/// Self-heal reset (CM5): record why (`kind` 3, `uptime_s` in `far`), let the UART drain, reset through the EL2
/// gate (`hvc #0`, the panic path). The next boot reports it like a crash. QEMU: never called (no reset gate).
#[cfg(feature = "cm5")]
pub fn self_heal_reset(uptime_s: u64, why: fmt::Arguments) -> ! {
    write(3, 0, 0, uptime_s, why);
    unsafe { core::arch::asm!("msr daifset, #0xf", options(nomem, nostack)) };
    for _ in 0..50_000_000u64 {
        core::hint::spin_loop();
    }
    unsafe { core::arch::asm!("hvc #0", options(noreturn)) }
}

