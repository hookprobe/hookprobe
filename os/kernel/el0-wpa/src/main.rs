//! ADR 0065 step 4g — `el0-wpa`, the resident EL0 WPA security server (operator decision 2026-11-15: the Wi-Fi bus
//! driver and the WPA control plane in two independently restartable EL0 servers; design
//! docs/design/wifi-el0-split.md).
//!
//! S1: the substrate only. The kernel maps this server's image, stack, control page, its PERSISTENT state pages and
//! the key-transfer page, in its own address space. A fault restores the image's writable pages and zeroes the
//! control page — the state pages survive (only a full wipe zeroes them). S2 moves the 4-way authenticator, the SAE
//! engine and the PMKSA cache in from el0-wifi and keeps them in the state pages.
#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use hal::wifisrvabi::{H_CMD, H_IN_LEN, H_MAGIC, H_OUT_LEN, H_R0, H_SERVED, H_STATUS, IN_MAX, IN_OFF, ST_BAD_CMD, ST_OK, ST_PANIC};
use hal::wpasrvabi::*;

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const CTRL: usize = BASE + CTRL_OFF;
const STATE: usize = BASE + STATE_OFF;
const KEYX: usize = BASE + KEYX_OFF;
const SYS_EXIT_USER: u64 = 6;

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((CTRL + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((CTRL + off) as *mut u32, v) }
}
fn io(off: usize, n: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((CTRL + off) as *mut u8, n) }
}
fn input() -> &'static [u8] {
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    &io(IN_OFF, IN_MAX)[..n]
}
fn exit(status: u32, r0: u32) -> ! {
    wr32(H_STATUS, status);
    wr32(H_R0, r0);
    wr32(H_OUT_LEN, 0);
    // nothing the kernel sent stays on the shared page once the command is done (key material arrives here in S2)
    io(IN_OFF, IN_MAX).fill(0);
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(ST_PANIC, 0)
}

/// The S1 test counter: the first 8 bytes of the persistent state.
fn counter() -> &'static mut u64 {
    unsafe { &mut *(STATE as *mut u64) }
}

/// Commands served by this incarnation (in .bss: reset by the kernel after a fault, unlike the state pages).
static mut SERVED: u32 = 0;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_CMD, 0);
    }
    let served = unsafe {
        SERVED += 1;
        SERVED
    };
    wr32(H_SERVED, served);
    match rd32(H_CMD) {
        CMD_INIT => exit(ST_OK, 0),
        CMD_STATE_BUMP => {
            let c = counter();
            *c = c.wrapping_add(1);
            exit(ST_OK, *c as u32)
        }
        CMD_STATE_READ => exit(ST_OK, *counter() as u32),
        CMD_KEYX_PUT => {
            let b = input();
            let n = b.len().min(0x1000);
            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), KEYX as *mut u8, n) };
            exit(ST_OK, n as u32)
        }
        CMD_SELFTEST_FAULT => unsafe {
            write_volatile(0x8 as *mut u32, 1);
            exit(ST_OK, 0)
        },
        _ => exit(ST_BAD_CMD, 0),
    }
}
