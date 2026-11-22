// SPDX-License-Identifier: AGPL-3.0-only
//! virtio-rng (virtio entropy device, type 4) over virtio-mmio — the entropy leaf of the **QEMU integration-test
//! profile only** (kernel feature `qemu-itest`, operator decision 2026-11-22). QEMU backs it with the host's
//! `/dev/urandom` (`-object rng-random,filename=/dev/urandom -device virtio-rng-device`).
//!
//! Never in a CM5 or cloud image: the kernel refuses `qemu-itest` together with `cm5` / `cloud` at compile time; the CM5
//! keeps the BCM2712 RNG200 and the cloud its SMCCC TRNG.
//!
//! Strict, like `rng200::next_word_strict`: `None` (the fail-closed signal) when the device is absent, does not
//! complete a request in time, returns fewer bytes than asked, or fails the continuous test (two identical consecutive
//! 64-bit words — SP 800-90B repetition-count spirit). A failed continuous test LATCHES: the source stays dead for the
//! rest of the boot. There is no timer, counter or constant substitute anywhere in this file.
use crate::mmu;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

const MMIO_BASE: usize = 0x0a00_0000;
const MMIO_STRIDE: usize = 0x200;
const MMIO_COUNT: usize = 32;
const MAGIC: usize = 0x000;
const DEVICE_ID: usize = 0x008;
const DEV_FEAT: usize = 0x010;
const DEV_FEAT_SEL: usize = 0x014;
const DRV_FEAT: usize = 0x020;
const DRV_FEAT_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const STATUS: usize = 0x070;
const Q_DESC_LO: usize = 0x080;
const Q_DESC_HI: usize = 0x084;
const Q_DRV_LO: usize = 0x090;
const Q_DRV_HI: usize = 0x094;
const Q_DEV_LO: usize = 0x0a0;
const Q_DEV_HI: usize = 0x0a4;

const VIRTIO_ID_ENTROPY: u32 = 4;
const S_ACK: u32 = 1;
const S_DRIVER: u32 = 2;
const S_DRIVER_OK: u32 = 4;
const S_FEAT_OK: u32 = 8;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const QSZ: usize = 4;
/// Bytes requested per device round trip (served 8 at a time).
const CHUNK: usize = 64;
/// Polls of the used ring before a request is declared lost (fail closed).
const SPIN_MAX: u64 = 50_000_000;

#[inline]
unsafe fn r(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}
#[inline]
unsafe fn w(base: usize, off: usize, v: u32) {
    write_volatile((base + off) as *mut u32, v)
}

struct Rng {
    base: usize,
    desc: usize,
    avail: usize,
    used: usize,
    buf: usize,
    avail_idx: u16,
    used_seen: u16,
    /// Unserved bytes of the last chunk: `buf[pos..CHUNK]`.
    pos: usize,
    prev: Option<u64>,
    dead: bool,
    pub words: u64,
    pub requests: u64,
}

static mut RNG: Option<Rng> = None;
static mut TRIED: bool = false;
/// Why the source is dead (for the boot log): 0 = alive, 1 = no device, 2 = feature negotiation refused, 3 = OOM,
/// 4 = request timeout, 5 = short fill, 6 = continuous test (repeated word).
static mut DEAD_WHY: u8 = 0;

fn find() -> Option<usize> {
    (0..MMIO_COUNT).map(|i| MMIO_BASE + i * MMIO_STRIDE).find(|&b| unsafe { r(b, MAGIC) == 0x7472_6976 && r(b, DEVICE_ID) == VIRTIO_ID_ENTROPY })
}

fn open() -> Result<Rng, u8> {
    let base = find().ok_or(1u8)?;
    unsafe {
        w(base, STATUS, 0);
        w(base, STATUS, S_ACK);
        w(base, STATUS, S_ACK | S_DRIVER);
        // VERSION_1 only (bit 32): the entropy device has no feature bits we need
        w(base, DEV_FEAT_SEL, 1);
        let dh = r(base, DEV_FEAT);
        w(base, DRV_FEAT_SEL, 0);
        w(base, DRV_FEAT, 0);
        w(base, DRV_FEAT_SEL, 1);
        w(base, DRV_FEAT, dh & 1);
        w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK);
        if r(base, STATUS) & S_FEAT_OK == 0 {
            return Err(2);
        }
        let (desc, avail, used, buf) = (mmu::reserve_region(4096), mmu::reserve_region(4096), mmu::reserve_region(4096), mmu::reserve_region(4096));
        if desc == 0 || avail == 0 || used == 0 || buf == 0 {
            return Err(3);
        }
        w(base, QUEUE_SEL, 0);
        let max = r(base, QUEUE_NUM_MAX) as usize;
        if max < QSZ {
            return Err(2);
        }
        w(base, QUEUE_NUM, QSZ as u32);
        w(base, Q_DESC_LO, desc as u32);
        w(base, Q_DESC_HI, (desc >> 32) as u32);
        w(base, Q_DRV_LO, avail as u32);
        w(base, Q_DRV_HI, (avail >> 32) as u32);
        w(base, Q_DEV_LO, used as u32);
        w(base, Q_DEV_HI, (used >> 32) as u32);
        w(base, QUEUE_READY, 1);
        w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK | S_DRIVER_OK);
        Ok(Rng { base, desc, avail, used, buf, avail_idx: 0, used_seen: 0, pos: CHUNK, prev: None, dead: false, words: 0, requests: 0 })
    }
}

impl Rng {
    /// One device round trip: CHUNK fresh bytes into `buf`, or the reason it failed.
    fn refill(&mut self) -> Result<(), u8> {
        unsafe {
            // poison the buffer so a device that reports bytes it did not write cannot hand back stale entropy
            core::ptr::write_bytes(self.buf as *mut u8, 0, CHUNK);
            write_volatile(self.desc as *mut u64, self.buf as u64);
            write_volatile((self.desc + 8) as *mut u32, CHUNK as u32);
            write_volatile((self.desc + 12) as *mut u16, VIRTQ_DESC_F_WRITE);
            write_volatile((self.desc + 14) as *mut u16, 0);
            let slot = (self.avail_idx as usize) % QSZ;
            write_volatile((self.avail + 4 + slot * 2) as *mut u16, 0u16);
            self.avail_idx = self.avail_idx.wrapping_add(1);
            fence(Ordering::SeqCst);
            write_volatile((self.avail + 2) as *mut u16, self.avail_idx);
            fence(Ordering::SeqCst);
            w(self.base, QUEUE_NOTIFY, 0);
            let mut spins = 0u64;
            loop {
                fence(Ordering::SeqCst);
                let idx = read_volatile((self.used + 2) as *const u16);
                if idx != self.used_seen {
                    let e = (self.used_seen as usize) % QSZ;
                    let len = read_volatile((self.used + 4 + e * 8 + 4) as *const u32) as usize;
                    self.used_seen = self.used_seen.wrapping_add(1);
                    self.requests += 1;
                    // the device may legally return fewer bytes; we never pad — a short fill is a failure here
                    if len < CHUNK {
                        return Err(5);
                    }
                    self.pos = 0;
                    return Ok(());
                }
                spins += 1;
                if spins > SPIN_MAX {
                    return Err(4);
                }
                core::hint::spin_loop();
            }
        }
    }

    fn next(&mut self) -> Option<u64> {
        if self.dead {
            return None;
        }
        if self.pos + 8 > CHUNK {
            if let Err(why) = self.refill() {
                self.kill(why);
                return None;
            }
        }
        let mut b = [0u8; 8];
        unsafe { core::ptr::copy_nonoverlapping((self.buf + self.pos) as *const u8, b.as_mut_ptr(), 8) };
        // consumed bytes are wiped from the device buffer at once
        unsafe { core::ptr::write_bytes((self.buf + self.pos) as *mut u8, 0, 8) };
        self.pos += 8;
        let v = u64::from_le_bytes(b);
        // continuous test: a repeated 64-bit word (incl. an all-zero device buffer read twice) kills the source
        if self.prev == Some(v) {
            self.kill(6);
            return None;
        }
        self.prev = Some(v);
        self.words += 1;
        Some(v)
    }

    fn kill(&mut self, why: u8) {
        self.dead = true;
        unsafe { DEAD_WHY = why };
    }
}

/// The strict 64-bit leaf for `entropy::HwTrng` under `qemu-itest`. `None` = fail closed (see the module doc).
pub fn next_word_strict() -> Option<u64> {
    unsafe {
        if !TRIED {
            TRIED = true;
            match open() {
                Ok(r) => RNG = Some(r),
                Err(why) => DEAD_WHY = why,
            }
        }
        (*core::ptr::addr_of_mut!(RNG)).as_mut()?.next()
    }
}

/// (present, words served, device requests, dead reason) — for the boot log and the self-tests.
pub fn status() -> (bool, u64, u64, u8) {
    unsafe {
        match (*core::ptr::addr_of!(RNG)).as_ref() {
            Some(r) => (true, r.words, r.requests, DEAD_WHY),
            None => (false, 0, 0, DEAD_WHY),
        }
    }
}

pub fn dead_reason(why: u8) -> &'static str {
    match why {
        0 => "alive",
        1 => "no virtio-rng device",
        2 => "feature/queue negotiation refused",
        3 => "out of memory for the queue",
        4 => "request timed out",
        5 => "short fill",
        6 => "continuous test failed (repeated word)",
        _ => "unknown",
    }
}
