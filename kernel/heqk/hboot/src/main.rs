#![no_std]
#![no_main]
//! HBoot — the HEQK boot manager (Phase 1 of the HookProbe boot architecture).
//!
//! Scope, deliberately small: console (owned by the stub), payload
//! verification (SHA-256 now, ed25519 slot reserved), measurement, relocation,
//! typed BootInfo handoff, EL1 launch. HBoot stays resident at EL2 as the
//! reboot/fault gate (`hvc #0`). No shell, no menus, no policy.

use boot_abi::*;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

mod sha256;

core::arch::global_asm!(include_str!("boot.s"));

const UART: usize = 0x1C_0003_0000;
const IMAGE_BASE: usize = 0x20_0000;

fn putc(b: u8) {
    unsafe {
        let mut spins = 0u32;
        while read_volatile((UART + 0x18) as *const u32) & (1 << 5) != 0 {
            spins += 1;
            if spins > 100_000 {
                return;
            }
        }
        write_volatile(UART as *mut u8, b);
    }
}

fn puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

fn puthex(v: u64) {
    puts("0x");
    for i in (0..16).rev() {
        let n = ((v >> (i * 4)) & 0xf) as u8;
        putc(if n < 10 { b'0' + n } else { b'a' + n - 10 });
    }
}

fn puthash(h: &[u8; 32]) {
    for byte in h {
        for n in [byte >> 4, byte & 0xf] {
            putc(if n < 10 { b'0' + n } else { b'a' + n - 10 });
        }
    }
}

extern "C" {
    fn hboot_launch_el1(entry: u64, bootinfo: u64) -> !;
    fn park() -> !;
}

#[no_mangle]
pub extern "C" fn hboot_main(dtb_pa: u64) -> ! {
    puts("\n+------------------------------------------+\n");
    puts("| HBoot v0 — HEQK boot manager (EL2)       |\n");
    puts("+------------------------------------------+\n");
    puts(" dtb : ");
    puthex(dtb_pa);
    puts("\n");

    // Locate and validate the payload header.
    let hdr = (IMAGE_BASE + HBOOT_PAYLOAD_OFFSET) as *const PayloadHeader;
    let (magic, size, load_pa, entry_off) = unsafe {
        (
            read_volatile(core::ptr::addr_of!((*hdr).magic)),
            read_volatile(core::ptr::addr_of!((*hdr).size)),
            read_volatile(core::ptr::addr_of!((*hdr).load_pa)),
            read_volatile(core::ptr::addr_of!((*hdr).entry_offset)),
        )
    };
    if magic != PAYLOAD_MAGIC {
        puts(" payload: BAD MAGIC ");
        puthex(magic);
        puts(" — refusing to boot\n");
        unsafe { park() }
    }
    if size == 0 || size > 0x100_0000 {
        puts(" payload: INSANE SIZE — refusing to boot\n");
        unsafe { park() }
    }
    puts(" payload: ");
    puthex(size);
    puts(" bytes, load ");
    puthex(load_pa);
    puts("\n");

    // Verify: SHA-256 over the payload body vs the header's hash.
    let body = (IMAGE_BASE + HBOOT_PAYLOAD_OFFSET + core::mem::size_of::<PayloadHeader>()) as *const u8;
    let computed = sha256::digest(unsafe { core::slice::from_raw_parts(body, size as usize) });
    let expected: [u8; 32] = unsafe { read_volatile(core::ptr::addr_of!((*hdr).sha256)) };
    puts(" measure: sha256=");
    puthash(&computed);
    puts("\n");
    if computed != expected {
        puts(" verify : FAIL — expected ");
        puthash(&expected);
        puts("\n refusing to boot\n");
        unsafe { park() }
    }
    puts(" verify : OK (sig slot: v1/ed25519 pending)\n");

    // Relocate the payload to its link address.
    unsafe {
        core::ptr::copy_nonoverlapping(body, load_pa as *mut u8, size as usize);
    }

    // BootInfo — the typed handoff (the kernel never parses the DTB).
    let bi = BOOTINFO_ADDR as *mut BootInfo;
    unsafe {
        write_volatile(
            bi,
            BootInfo {
                magic: BOOTINFO_MAGIC,
                version: 1,
                dtb_pa,
                kernel_pa: load_pa,
                kernel_size: size,
                kernel_hash: computed,
                hboot_version: 0,
                el2_gate: 1,
            },
        );
    }

    puts(" launch : EL1 entry ");
    puthex(load_pa + entry_off);
    puts("\n\n");
    unsafe { hboot_launch_el1(load_pa + entry_off, BOOTINFO_ADDR as u64) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    puts("\nHBoot PANIC\n");
    unsafe { park() }
}
