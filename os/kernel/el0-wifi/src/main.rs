//! ADR 0065 — `el0-wifi`, the resident EL0 Wi-Fi driver server.
//!
//! Step 2: the substrate. The server is RESIDENT: the kernel maps its image, stack, control page, the device page it
//! was granted, and the two frame rings ONCE; each command re-enters `_start`, and the server's `.data` / `.bss`
//! persist between commands until a fault makes the kernel reset them. The device in this step is a fake (one RAM
//! page, `hal::wifisrvabi::FDEV_*`); step 4 puts the CYW43455's SDHCI registers there.
#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use hal::el0ring as ring;
use hal::wifisrvabi::*;

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const CTRL: usize = BASE + CTRL_OFF;
const DEV: usize = BASE + DEV_OFF;
const SYS_EXIT_USER: u64 = 6;

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((CTRL + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((CTRL + off) as *mut u32, v) }
}
fn exit(status: u32, r0: u32) -> ! {
    wr32(H_STATUS, status);
    wr32(H_R0, r0);
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(ST_PANIC, 0)
}

/// Commands served by this incarnation (in .bss: survives between calls, reset by the kernel after a fault).
static mut SERVED: u32 = 0;

fn ring_at(off: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((BASE + off) as *mut u8, ring::RING_BYTES) }
}
fn dev16(off: usize) -> u16 {
    unsafe { read_volatile((DEV + off) as *const u16) }
}
fn set_dev16(off: usize, v: u16) {
    unsafe { write_volatile((DEV + off) as *mut u16, v) }
}
fn dev(off: usize, n: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((DEV + off) as *mut u8, n) }
}

/// One poll of the fake device: its received frame (if any) into the RX ring; one TX-ring frame (if any) out to it.
fn poll() -> u32 {
    let mut moved = 0u32;
    let n = dev16(FDEV_RX_LEN) as usize;
    if n > 0 && n <= FDEV_FRAME_MAX && ring::push(ring_at(RX_OFF), &dev(FDEV_RX_DATA, n)[..]) {
        set_dev16(FDEV_RX_LEN, 0);
        moved += 1;
    }
    let mut buf = [0u8; FDEV_FRAME_MAX];
    if let ring::Pop::Frame(k) = ring::pop(ring_at(TX_OFF), &mut buf) {
        dev(FDEV_TX_DATA, k).copy_from_slice(&buf[..k]);
        set_dev16(FDEV_TX_LEN, k as u16);
        moved += 1;
    }
    moved
}

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
        CMD_POLL => exit(ST_OK, poll()),
        CMD_SELFTEST_BAD_RING => {
            // a hostile driver: claim 1000 frames pending in the RX ring
            let r = ring_at(RX_OFF);
            r[0..4].copy_from_slice(&1000u32.to_le_bytes());
            exit(ST_OK, 0)
        }
        CMD_SELFTEST_FAULT => unsafe {
            write_volatile(0x8 as *mut u32, 1);
            exit(ST_OK, 0)
        },
        _ => exit(ST_BAD_CMD, 0),
    }
}
