// SPDX-License-Identifier: AGPL-3.0-only
//! PCIe enumeration through ECAM (from ACPI MCFG). Read-only: it never writes config space, so nothing a device
//! does depends on it yet. It finds the virtio-pci functions (vendor 0x1AF4) and walks their capability lists for
//! the virtio 1.x vendor capabilities (common / notify / isr / device cfg) a modern transport driver needs.

use crate::acpi::Ecam;

/// The MCFG base address is that of bus 0 of the segment, whatever its start bus (PCI Firmware spec; Linux
/// pci_mmcfg uses it the same way), so the bus offset is never rebased on `bus_start`.
fn cfg(e: &Ecam, bus: u8, dev: u8, func: u8, off: u16) -> u64 {
    e.base + ((bus as u64) << 20) + ((dev as u64) << 15) + ((func as u64) << 12) + off as u64
}
fn r8(a: u64) -> u8 {
    unsafe { core::ptr::read_volatile(a as *const u8) }
}
fn r16(a: u64) -> u16 {
    unsafe { core::ptr::read_volatile(a as *const u16) }
}

#[derive(Clone, Copy, Default)]
pub struct Virtio {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub device_id: u16,
    pub kind: &'static str,
    pub modern: bool,
    pub caps: u8, // bitmask of virtio_pci_cap cfg_type 1..5 seen
}

pub struct Scan {
    pub functions: usize,
    pub bridges: usize,
    pub virtio: [Virtio; 8],
    pub n_virtio: usize,
}

fn kind(id: u16) -> &'static str {
    match id {
        0x1000 | 0x1041 => "net",
        0x1001 | 0x1042 => "blk",
        0x1005 | 0x1044 => "rng",
        _ => "other",
    }
}

/// Walk the standard capability list for virtio vendor capabilities (ID 0x09); bounded to 48 hops.
fn virtio_caps(e: &Ecam, b: u8, d: u8, f: u8) -> u8 {
    if r16(cfg(e, b, d, f, 0x06)) & (1 << 4) == 0 {
        return 0; // no capability list
    }
    let mut mask = 0u8;
    let mut p = r8(cfg(e, b, d, f, 0x34)) & 0xFC;
    let mut hops = 0;
    while p >= 0x40 && hops < 48 {
        let id = r8(cfg(e, b, d, f, p as u16));
        if id == 0x09 {
            let ty = r8(cfg(e, b, d, f, p as u16 + 3));
            if (1..=5).contains(&ty) {
                mask |= 1 << ty;
            }
        }
        p = r8(cfg(e, b, d, f, p as u16 + 1)) & 0xFC;
        hops += 1;
    }
    mask
}

pub fn scan(e: &Ecam) -> Scan {
    let mut s = Scan { functions: 0, bridges: 0, virtio: [Virtio::default(); 8], n_virtio: 0 };
    for bus in e.bus_start..=e.bus_end {
        for dev in 0..32u8 {
            let funcs = if r8(cfg(e, bus, dev, 0, 0x0E)) & 0x80 != 0 { 8 } else { 1 };
            for func in 0..funcs {
                let vendor = r16(cfg(e, bus, dev, func, 0x00));
                if vendor == 0xFFFF {
                    if func == 0 {
                        break;
                    }
                    continue;
                }
                s.functions += 1;
                if r8(cfg(e, bus, dev, func, 0x0E)) & 0x7F == 1 {
                    s.bridges += 1;
                }
                let did = r16(cfg(e, bus, dev, func, 0x02));
                if vendor == 0x1AF4 && (0x1000..=0x107F).contains(&did) && s.n_virtio < s.virtio.len() {
                    let caps = virtio_caps(e, bus, dev, func);
                    s.virtio[s.n_virtio] =
                        Virtio { bus, dev, func, device_id: did, kind: kind(did), modern: caps & 0b11110 == 0b11110, caps };
                    s.n_virtio += 1;
                }
            }
        }
    }
    s
}
