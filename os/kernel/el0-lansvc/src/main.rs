//! The EL0 LAN-services server (ADR 0050 D4 step 2). Each bounded excursion runs ONE command from the shared IO
//! region (`hal::lansvcabi`) and exits back to the kernel with `SYS_EXIT_USER`. It parses what every Wi-Fi client
//! and the upstream resolver send to Shield — a DNS query, a DNS answer — with the kernel's own `dnswire.rs`, so a
//! parser bug costs this server (the kernel resets it and passes the message, ADR 0050 D5), never the kernel.
//! Allocation-free; no state survives a command.
#![no_std]
#![no_main]

#[path = "../../kernel/src/dnswire.rs"]
#[allow(dead_code)]
mod dnswire;

use core::ptr::{read_volatile, write_volatile};
use hal::lansvcabi::*;

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const IO: usize = BASE + IO_OFF;
const SYS_EXIT_USER: u64 = 6;

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

/// The response walk result lives in .bss (8 KiB+; the stack stays small).
static mut WALK: dnswire::Walk = dnswire::WALK0;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_CMD, 0);
    }
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    let mut msg = [0u8; IN_MAX];
    msg[..n].copy_from_slice(&io(IN_OFF, n)[..]);
    let dns = &msg[..n];
    let out = io(OUT_OFF, OUT_MAX);
    match rd32(H_CMD) {
        CMD_DNS_QUERY => match dnswire::parse_query(dns) {
            Some(q) => {
                let nl = q.nl.min(255);
                out[0..2].copy_from_slice(&(nl as u16).to_le_bytes());
                out[2..4].copy_from_slice(&q.qtype.to_le_bytes());
                out[4..8].copy_from_slice(&(q.qend as u32).to_le_bytes());
                out[8] = q.edns as u8;
                out[Q_REC_HDR..Q_REC_HDR + nl].copy_from_slice(&q.name[..nl]);
                exit(ST_OK, Q_REC_HDR + nl)
            }
            None => exit(ST_NONE, 0),
        },
        CMD_DNS_WALK => {
            #[allow(static_mut_refs)]
            let w = unsafe { &mut WALK };
            if dnswire::walk_answers(dns, w).is_none() {
                exit(ST_NONE, 0);
            }
            let k = w.ncname.min(WALK_MAX_CNAMES);
            out[0..2].copy_from_slice(&(w.qnl.min(255) as u16).to_le_bytes());
            out[2..4].copy_from_slice(&(k as u16).to_le_bytes());
            out[4..8].copy_from_slice(&(w.qend as u32).to_le_bytes());
            out[8..8 + 256].copy_from_slice(&w.qname);
            for i in 0..k {
                let o = WALK_HDR + i * WALK_STRIDE;
                out[o..o + 2].copy_from_slice(&(w.cnl[i].min(255) as u16).to_le_bytes());
                out[o + 2..o + 2 + 256].copy_from_slice(&w.cnames[i]);
            }
            exit(ST_OK, WALK_HDR + k * WALK_STRIDE)
        }
        CMD_SELFTEST_FAULT => unsafe { core::ptr::read_volatile(0x10 as *const u32) as usize as *const u8; core::ptr::write_volatile(0x8 as *mut u32, 1); exit(ST_OK, 0) },
        _ => exit(ST_BAD_CMD, 0),
    }
}
