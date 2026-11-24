// SPDX-License-Identifier: AGPL-3.0-only
//! el0-harness: the Conductor harness (conductor-core) as an EL0 excursion server for heqk.
//!
//! One command per excursion from the shared IO region (`conductor_core::abi`); the harness state lives in
//! this server's .bss between excursions. It holds no key, no network and no storage capability: every
//! effect it wants is an action the kernel performs. A panic ends only the excursion (ST_PANIC); the
//! kernel then resets the server, which forgets the job (the kernel ends its lease).
//!
//! C0: built and measured only. Wiring into os/kernel/kernel/build.rs, the address range and moving the
//! ABI into hal/ are HomePods decisions.
#![no_std]
#![no_main]

use conductor_core::abi::*;
use conductor_core::harness::{Actions, Harness};
use core::ptr::{read_volatile, write_volatile};

/// PROPOSED layout (unassigned): image, then stack, then the IO region.
const BASE: usize = 0xBE80_0000;
pub const IMAGE_MAX: usize = 0x2_0000;
pub const STACK_OFF: usize = IMAGE_MAX;
pub const STACK_SIZE: usize = 0x8000;
pub const IO_BASE: usize = BASE + STACK_OFF + STACK_SIZE;
const SYS_EXIT_USER: u64 = 6;

/// All-zero by construction (conductor-core keeps no niche-encoded `Option` in its state), so this lands
/// in .bss and adds nothing to the ELF the kernel embeds. `zero_state_is_bss` in the bench checks it.
static mut HARNESS: Harness = Harness::new();

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
    // SAFETY: one excursion at a time, single-threaded server; SERVER is only touched here.
    let h = unsafe { &mut *core::ptr::addr_of_mut!(HARNESS) };
    match rd32(H_CMD) {
        CMD_LOAD => {
            if inb.len() < ENV_LEN {
                exit(ST_BAD_INPUT, 0);
            }
            let (env, job) = inb.split_at(ENV_LEN);
            let Some(env) = decode_env(env) else { exit(ST_BAD_INPUT, 0) };
            match h.load(job, env) {
                Ok(()) => exit(ST_OK, 0),
                Err(_) => exit(ST_BAD_INPUT, 0),
            }
        }
        CMD_EVENT => {
            let Some((now, ev)) = decode_event(inb) else { exit(ST_BAD_INPUT, 0) };
            let mut out = Actions::new();
            h.handle(now, ev, &mut out);
            match encode_output(&out, h, io(OUT_OFF, OUT_MAX)) {
                Some(len) => exit(ST_OK, len),
                None => exit(ST_BAD_INPUT, 0),
            }
        }
        _ => exit(ST_BAD_INPUT, 0),
    }
}
