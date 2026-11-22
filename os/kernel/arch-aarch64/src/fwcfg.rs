// SPDX-License-Identifier: AGPL-3.0-only
//! QEMU fw_cfg (MMIO, `-M virt` at 0x0902_0000), read-only — the per-VM key-wrapping secret of the **QEMU
//! integration-test profile only** (kernel `qemu-itest`): `-fw_cfg name=opt/hookprobe/kek,file=<per-vm>/kek.bin`.
//! The KEK never touches the backing volume (operator decision 2026-11-22: "protected separately").
//!
//! Interface (QEMU docs/specs/fw_cfg.rst): selector register at +8 (16-bit, big-endian), data register at +0 (byte
//! stream). Item 0x0000 = signature "QEMU"; item 0x0019 = the file directory: BE u32 count, then entries of
//! { BE u32 size, BE u16 select, u16 reserved, char name[56] }.
use core::ptr::{read_volatile, write_volatile};

const BASE: usize = 0x0902_0000;
const DATA: usize = BASE;
const SEL: usize = BASE + 8;
const SIG: u16 = 0x0000;
const FILE_DIR: u16 = 0x0019;

fn select(key: u16) {
    unsafe { write_volatile(SEL as *mut u16, key.to_be()) };
}
fn byte() -> u8 {
    unsafe { read_volatile(DATA as *const u8) }
}
fn read(out: &mut [u8]) {
    for b in out.iter_mut() {
        *b = byte();
    }
}

/// fw_cfg present (signature "QEMU")?
pub fn present() -> bool {
    select(SIG);
    let mut s = [0u8; 4];
    read(&mut s);
    &s == b"QEMU"
}

/// Copy the fw_cfg file `name` into `out`. Some(size of the file) — the caller checks it equals what it expects;
/// at most `out.len()` bytes are copied. None = no fw_cfg / no such file.
pub fn read_file(name: &[u8], out: &mut [u8]) -> Option<usize> {
    if !present() || name.len() >= 56 {
        return None;
    }
    select(FILE_DIR);
    let mut c = [0u8; 4];
    read(&mut c);
    let count = u32::from_be_bytes(c).min(1024);
    let mut found: Option<(u16, usize)> = None;
    for _ in 0..count {
        let mut e = [0u8; 64];
        read(&mut e);
        let size = u32::from_be_bytes([e[0], e[1], e[2], e[3]]) as usize;
        let sel = u16::from_be_bytes([e[4], e[5]]);
        let n = &e[8..64];
        let nl = n.iter().position(|b| *b == 0).unwrap_or(56);
        if found.is_none() && &n[..nl] == name {
            found = Some((sel, size));
        }
    }
    let (sel, size) = found?;
    select(sel);
    let k = size.min(out.len());
    read(&mut out[..k]);
    Some(size)
}
