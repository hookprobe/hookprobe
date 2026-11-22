// SPDX-License-Identifier: AGPL-3.0-only
//! el0-neuro: the HookProbe temporal security engine (stage 1, N0) as an EL0 excursion server.
//!
//! Each excursion runs one command from the shared IO region (`abi.rs`) and exits. The per-device
//! behavioural memory (`neuro_core::Dna`) and the hour aggregators persist in this server's .bss across
//! excursions.
//!
//! Integer-only and allocation-free; builds for `aarch64-unknown-none-softfloat` like every heqk server.
//! The server parses untrusted input defensively, never decides enforcement (ADR 0023, C9), and holds no
//! network, storage or policy capability. It returns scores. They are EVIDENCE ONLY: the kernel attaches them
//! to the evidence graph and to the explainer's context, and never raises an alert or an enforcement action
//! from them (docs/research/neuro/17 decision, 20 contract).
#![no_std]
#![no_main]

mod abi;

use abi::*;
use core::ptr::{read_volatile, write_volatile};
use neuro_core::{Dna, Driver, HourAgg, CALM_Q8};

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const IO: usize = BASE + IO_OFF;
const SYS_EXIT_USER: u64 = 6;
/// The engine revision INFO reports (bump when neuro-core's scoring changes; the golden vectors pin it).
const ENGINE_REV: u32 = 1;

/// Devices tracked (`hal::neuroabi::DEVICES`). ~1.3 KiB each (`neuro_core::bytes_per_device`); 64 devices ≈ 85 KiB of .bss.
const _: () = assert!(DEVICES * neuro_core::bytes_per_device() + 0x8000 <= IMAGE_MAX);

struct Engine {
    dna: [Dna; DEVICES],
    agg: [HourAgg; DEVICES],
    active: [bool; DEVICES],
    /// A slot is initialised on first use. The table is all-zero at load, so it lives in .bss and adds
    /// nothing to the ELF the kernel embeds (the kernel image has ~33 KB of headroom, research doc 00).
    init: [bool; DEVICES],
    /// v1.1 CMD_HEALTH counters (wrapping; the kernel reads deltas).
    health: Health,
}

impl Engine {
    fn slot(&mut self, dev: usize) {
        if !self.init[dev] {
            self.dna[dev] = Dna::new();
            self.agg[dev].reset();
            self.active[dev] = false;
            self.init[dev] = true;
        }
    }
}

// All-zero bytes are a valid Engine (integers, bools, byte arrays only), so zeroed() is sound and goes to .bss.
static mut ENGINE: core::mem::MaybeUninit<Engine> = core::mem::MaybeUninit::zeroed();

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((IO + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((IO + off) as *mut u32, v) }
}
fn io(off: usize, len: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((IO + off) as *mut u8, len) }
}
fn exit(status: u32, out_len: usize) -> ! {
    wr32(H_STATUS, status);
    wr32(H_OUT_LEN, out_len as u32);
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(ST_PANIC, 0)
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn le48(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a[..6].copy_from_slice(&b[..6]);
    u64::from_le_bytes(a)
}
fn sat16(v: i64) -> u16 {
    v.clamp(0, 65535) as u16
}

fn events(e: &mut Engine, inb: &[u8]) -> u32 {
    let mut bad = false;
    for rec in inb.as_chunks::<EV_SIZE>().0 {
        let (kind, flags, dev) = (rec[0], rec[1], le16(&rec[2..]) as usize);
        if dev >= DEVICES {
            bad = true;
            e.health.events_bad = e.health.events_bad.wrapping_add(1);
            continue;
        }
        e.slot(dev);
        let fp = le32(&rec[4..]);
        let bytes = le48(&rec[8..]);
        let conns = le16(&rec[14..]) as u64;
        let (mem, agg) = (&e.dna[dev], &mut e.agg[dev]);
        match kind {
            EV_FLOW => agg.add_flow(mem, Some(fp), bytes, conns),
            EV_VOLUME => agg.add_flow(mem, None, bytes, conns),
            EV_DNS => agg.add_dns(mem, fp, flags & 1 == 1),
            _ => {
                bad = true;
                e.health.events_bad = e.health.events_bad.wrapping_add(1);
                continue;
            }
        }
        e.health.events_ok = e.health.events_ok.wrapping_add(1);
        e.active[dev] = true;
    }
    if bad || !inb.len().is_multiple_of(EV_SIZE) {
        e.health.batches_bad = e.health.batches_bad.wrapping_add(1);
        ST_BAD_INPUT
    } else {
        ST_OK
    }
}

fn close_hour(e: &mut Engine, hr: usize, out: &mut [u8]) -> usize {
    let mut n = 0;
    for dev in 0..DEVICES {
        if !e.active[dev] {
            continue;
        }
        let s = e.dna[dev].close_hour(hr, &e.agg[dev]);
        e.agg[dev].reset();
        e.active[dev] = false;
        if n + RES_SIZE > out.len() {
            e.health.reports_dropped = e.health.reports_dropped.wrapping_add(1);
            continue; // OUT full: the device was still scored and learned; only its report is dropped
        }
        let r = &mut out[n..n + RES_SIZE];
        r[0..2].copy_from_slice(&(dev as u16).to_le_bytes());
        r[2] = match s.driver() {
            Driver::Volume => 0,
            Driver::FanOut => 1,
            Driver::NovelPeers => 2,
            Driver::Dns => 3,
            Driver::Activity => 4,
        };
        r[3] = (s.score >= CALM_Q8) as u8;
        r[4..8].copy_from_slice(&(s.score.clamp(0, u32::MAX as i64) as u32).to_le_bytes());
        for (i, v) in [s.vol, s.fan, s.novel, s.dns, s.act].iter().enumerate() {
            r[8 + 2 * i..10 + 2 * i].copy_from_slice(&sat16(*v).to_le_bytes());
        }
        r[18..20].copy_from_slice(&0u16.to_le_bytes());
        n += RES_SIZE;
    }
    e.health.hours_closed = e.health.hours_closed.wrapping_add(1);
    n
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_CMD, 0);
    }
    // v1.1: a kernel that names an ABI major we do not speak is refused (0 = a v1.0 kernel, no version word)
    let abi = rd32(H_ABI);
    if abi != 0 && abi >> 16 != ABI_MAJOR as u32 {
        exit(ST_BAD_VERSION, 0);
    }
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    // SAFETY: one excursion at a time, single-threaded server; ENGINE is only touched here.
    let e = unsafe { (*core::ptr::addr_of_mut!(ENGINE)).assume_init_mut() };
    match rd32(H_CMD) {
        CMD_EVENTS => {
            let st = events(e, &io(IN_OFF, n)[..]);
            exit(st, 0)
        }
        CMD_CLOSE_HOUR => {
            if n < 1 {
                exit(ST_BAD_INPUT, 0);
            }
            let hr = io(IN_OFF, 1)[0] as usize;
            if hr >= 24 {
                exit(ST_BAD_INPUT, 0);
            }
            let len = close_hour(e, hr, io(OUT_OFF, OUT_MAX));
            exit(ST_OK, len)
        }
        CMD_RESET_DEV => {
            if n < 2 {
                exit(ST_BAD_INPUT, 0);
            }
            let dev = le16(io(IN_OFF, 2)) as usize;
            if dev >= DEVICES {
                exit(ST_BAD_INPUT, 0);
            }
            e.init[dev] = false; // re-initialised on next use
            e.active[dev] = false;
            exit(ST_OK, 0)
        }
        CMD_INFO => {
            let o = io(OUT_OFF, INFO_LEN);
            o[0..2].copy_from_slice(&(DEVICES as u16).to_le_bytes());
            o[2..6].copy_from_slice(&(neuro_core::bytes_per_device() as u32).to_le_bytes());
            o[6..8].copy_from_slice(&ABI_MAJOR.to_le_bytes());
            o[8..10].copy_from_slice(&ABI_MINOR.to_le_bytes());
            o[10..12].copy_from_slice(&CAP_HEALTH.to_le_bytes());
            o[12..16].copy_from_slice(&ENGINE_REV.to_le_bytes());
            exit(ST_OK, INFO_LEN)
        }
        CMD_HEALTH => {
            let mut h = e.health;
            h.active = e.active.iter().filter(|a| **a).count() as u16;
            h.slots_used = e.init.iter().filter(|a| **a).count() as u16;
            io(OUT_OFF, HEALTH_LEN).copy_from_slice(&encode_health(&h));
            exit(ST_OK, HEALTH_LEN)
        }
        CMD_SELFTEST_FAULT => panic!("requested fault"),
        _ => exit(ST_BAD_CMD, 0),
    }
}
