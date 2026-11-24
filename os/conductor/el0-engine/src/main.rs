// SPDX-License-Identifier: AGPL-3.0-only
//! el0-engine: the integer specialist engine as an EL0 excursion server.
//!
//! CMD_ADMIT: IN = a model package. It is copied into this server's own memory and admitted (every bound,
//!            shape and overflow check). OUT = input_len u16, output_len u16, arena u32, macs u64, root[32].
//! CMD_RUN:   IN = the input vector. OUT = the output vector. Fixed work, no allocation.
//!
//! The server holds no capability: it sees one IO page. A fault ends only the excursion. In C1 the kernel
//! verifies the package signature before handing it over (Neuro request R5).
#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use neuro_engine::{Model, MAX_ARENA};

const BASE: usize = 0xBE90_0000;
const IMAGE_MAX: usize = 0x4_0000;
const STACK_SIZE: usize = 0x4000;
const IO_BASE: usize = BASE + IMAGE_MAX + STACK_SIZE;
const MAGIC: u32 = u32::from_le_bytes(*b"HQNG");
const H_MAGIC: usize = 0;
const H_CMD: usize = 4;
const H_IN_LEN: usize = 8;
const H_STATUS: usize = 12;
const H_OUT_LEN: usize = 16;
const IN_OFF: usize = 0x40;
const IN_MAX: usize = 0x1_0000;
const OUT_OFF: usize = IN_OFF + IN_MAX;
const OUT_MAX: usize = 0x1000;
const CMD_ADMIT: u32 = 1;
const CMD_RUN: u32 = 2;
const ST_OK: u32 = 0;
const ST_BAD_INPUT: u32 = 1;
const ST_REFUSED: u32 = 2;
const ST_PANIC: u32 = 0xdead;
const SYS_EXIT_USER: u64 = 6;

/// Largest package this server keeps (specialists are small; language models need the R3 model region).
const PKG_MAX: usize = IN_MAX;

// All-zero at load, so everything below is .bss.
static mut PKG: [u8; PKG_MAX] = [0; PKG_MAX];
static mut PKG_LEN: usize = 0;
static mut ARENA: [u8; MAX_ARENA] = [0; MAX_ARENA];

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((IO_BASE + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((IO_BASE + off) as *mut u32, v) }
}
fn io(off: usize, len: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((IO_BASE + off) as *mut u8, len) }
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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_INPUT, 0);
    }
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    let inb: &[u8] = io(IN_OFF, n);
    // SAFETY: one excursion at a time, single-threaded server; these statics are only touched here.
    let (pkg, pkg_len, arena) = unsafe { (&mut *core::ptr::addr_of_mut!(PKG), &mut *core::ptr::addr_of_mut!(PKG_LEN), &mut *core::ptr::addr_of_mut!(ARENA)) };
    match rd32(H_CMD) {
        CMD_ADMIT => {
            *pkg_len = 0;
            let Some(dst) = pkg.get_mut(..n) else { exit(ST_BAD_INPUT, 0) };
            dst.copy_from_slice(inb);
            match Model::admit(&pkg[..n]) {
                Err(_) => exit(ST_REFUSED, 0),
                Ok(m) => {
                    *pkg_len = n;
                    let o = io(OUT_OFF, 48);
                    o[0..2].copy_from_slice(&(m.input_len() as u16).to_le_bytes());
                    o[2..4].copy_from_slice(&(m.output_len() as u16).to_le_bytes());
                    o[4..8].copy_from_slice(&(m.arena_bytes() as u32).to_le_bytes());
                    o[8..16].copy_from_slice(&m.macs().to_le_bytes());
                    o[16..48].copy_from_slice(m.root());
                    exit(ST_OK, 48)
                }
            }
        }
        CMD_RUN => {
            // The stored package was fully checked at CMD_ADMIT; re-deriving the plan from it here keeps the
            // server free of self-referential state. (A specialist package is a few hundred bytes.)
            let Ok(m) = Model::admit(&pkg[..*pkg_len]) else { exit(ST_REFUSED, 0) };
            let out_len = m.output_len();
            if out_len > OUT_MAX {
                exit(ST_BAD_INPUT, 0);
            }
            match m.run(arena, inb, io(OUT_OFF, out_len)) {
                Ok(()) => exit(ST_OK, out_len),
                Err(_) => exit(ST_BAD_INPUT, 0),
            }
        }
        _ => exit(ST_BAD_INPUT, 0),
    }
}
