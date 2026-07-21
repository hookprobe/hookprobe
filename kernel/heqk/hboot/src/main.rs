#![no_std]
#![no_main]
//! HBoot — the HEQK boot manager (Phase 1 of the HookProbe boot architecture).
//!
//! Scope, deliberately small: console (owned by the stub), HYBRID secure-boot
//! verification (measure with SHA-256, then require BOTH an ed25519 AND an
//! SLH-DSA / FIPS-205 signature — quantum-safe: breaking boot needs breaking
//! classical ECC AND post-quantum), relocation, typed BootInfo handoff, EL1
//! launch. HBoot stays resident at EL2 as the reboot/fault gate (`hvc #0`).
//! No shell, no menus, no policy.

use boot_abi::*;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use ed25519_compact::{PublicKey as EdPublicKey, Signature as EdSignature};
use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Verifier};

mod sha256;
mod trusted_keys;

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

    // MEASURE: SHA-256 over the payload body. Verification binds to THIS
    // recomputed hash, never the header's stored copy — so a tampered payload
    // fails even if the attacker also rewrites the stored hash.
    let body = (IMAGE_BASE + HBOOT_PAYLOAD_OFFSET + core::mem::size_of::<PayloadHeader>()) as *const u8;
    let computed = sha256::digest(unsafe { core::slice::from_raw_parts(body, size as usize) });
    puts(" measure: sha256=");
    puthash(&computed);
    puts("\n");

    // HYBRID VERIFY: both signatures over the recomputed hash, with the
    // trusted public keys embedded in HBoot (never taken from the image).
    let ed_sig_bytes: [u8; ED25519_SIG_LEN] =
        unsafe { read_volatile(core::ptr::addr_of!((*hdr).ed25519_sig)) };
    let pq_sig_bytes: [u8; SLHDSA_SIG_LEN] =
        unsafe { read_volatile(core::ptr::addr_of!((*hdr).slhdsa_sig)) };

    // Classical: ed25519.
    let ed_ok = (|| {
        let pk = EdPublicKey::from_slice(&trusted_keys::ED25519_PUBKEY).ok()?;
        let sig = EdSignature::from_slice(&ed_sig_bytes).ok()?;
        pk.verify(computed, &sig).ok()
    })()
    .is_some();
    puts(if ed_ok { " verify : ed25519  OK\n" } else { " verify : ed25519  FAIL\n" });

    // Post-quantum: SLH-DSA-SHA2-128s (FIPS 205) — hash-based, quantum-safe.
    let pq_ok = match slh_dsa_sha2_128s::PublicKey::try_from_bytes(&trusted_keys::SLHDSA_PUBKEY) {
        Ok(pk) => pk.verify(&computed, &pq_sig_bytes, SIG_CTX),
        Err(_) => false,
    };
    puts(if pq_ok { " verify : SLH-DSA OK (quantum-safe)\n" } else { " verify : SLH-DSA FAIL\n" });

    // BOTH required. Either failing = refuse to boot.
    if !ed_ok || !pq_ok {
        puts(" secure boot: FAIL — hybrid signature invalid, refusing to boot\n");
        unsafe { park() }
    }
    puts(" secure boot: PASS (ed25519 AND SLH-DSA)\n");

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
                version: 2,
                dtb_pa,
                kernel_pa: load_pa,
                kernel_size: size,
                kernel_hash: computed,
                hboot_version: 1,
                el2_gate: 1,
                verify_flags: VERIFY_ED25519 | VERIFY_SLHDSA,
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
