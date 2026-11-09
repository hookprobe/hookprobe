//! Virtio transport seam: the register-level operations the virtio drivers need, behind
//! one type with two backends.
//!
//! * `Mmio` — virtio-mmio v2 (QEMU `virt` default, the existing QEMU gates). Byte-for-byte
//!   the access pattern the drivers used before this seam existed.
//! * `Pci` (feature `pci`) — virtio-pci MODERN (virtio 1.x, capability-based), the arm64
//!   cloud: OCI Ampere A1 exposes modern-only virtio-net 1af4:1041 / virtio-scsi 1af4:1048.
//!   Poll-mode: MSI-X stays at NO_VECTOR (the drivers poll used rings, as on mmio).
//!
//! The split-virtqueue memory layout, buffers and all DEVICE-supplied-value bounds checks
//! stay in the drivers — only register plumbing lives here.

use core::ptr::{read_volatile, write_volatile};

// ---- virtio-mmio (v2) ----
const MMIO_BASE: usize = 0x0a00_0000;
const MMIO_STRIDE: usize = 0x200;
const MMIO_COUNT: usize = 32;
const M_MAGIC: usize = 0x000;
const M_DEVICE_ID: usize = 0x008;
const M_DEV_FEAT: usize = 0x010;
const M_DEV_FEAT_SEL: usize = 0x014;
const M_DRV_FEAT: usize = 0x020;
const M_DRV_FEAT_SEL: usize = 0x024;
const M_QUEUE_SEL: usize = 0x030;
const M_QUEUE_NUM: usize = 0x038;
const M_QUEUE_READY: usize = 0x044;
const M_QUEUE_NOTIFY: usize = 0x050;
const M_STATUS: usize = 0x070;
const M_Q_DESC_LO: usize = 0x080;
const M_Q_DESC_HI: usize = 0x084;
const M_Q_DRV_LO: usize = 0x090;
const M_Q_DRV_HI: usize = 0x094;
const M_Q_DEV_LO: usize = 0x0a0;
const M_Q_DEV_HI: usize = 0x0a4;
const M_CONFIG: usize = 0x100;

#[inline]
unsafe fn r32(a: usize) -> u32 {
    read_volatile(a as *const u32)
}
#[inline]
unsafe fn w32(a: usize, v: u32) {
    write_volatile(a as *mut u32, v)
}

/// virtio-pci modern register windows, as kernel VAs.
#[cfg(feature = "pci")]
pub struct PciRegs {
    common: usize,
    notify: usize,
    notify_mult: u32,
    device: usize,
    pub bdf: crate::pci::Bdf,
}

pub enum Transport {
    Mmio(usize),
    #[cfg(feature = "pci")]
    Pci(PciRegs),
}

// virtio-pci common configuration structure offsets (virtio 1.x §4.1.4.3).
#[cfg(feature = "pci")]
mod cc {
    pub const DEV_FEAT_SEL: usize = 0x00;
    pub const DEV_FEAT: usize = 0x04;
    pub const DRV_FEAT_SEL: usize = 0x08;
    pub const DRV_FEAT: usize = 0x0c;
    pub const STATUS: usize = 0x14;
    pub const Q_SELECT: usize = 0x16;
    pub const Q_SIZE: usize = 0x18;
    pub const Q_MSIX: usize = 0x1a;
    pub const Q_ENABLE: usize = 0x1c;
    pub const Q_NOTIFY_OFF: usize = 0x1e;
    pub const Q_DESC: usize = 0x20;
    pub const Q_DRIVER: usize = 0x28;
    pub const Q_DEVICE: usize = 0x30;
}

#[cfg(feature = "pci")]
const VIRTIO_PCI_VENDOR: u16 = 0x1af4;
#[cfg(feature = "pci")]
const NO_VECTOR: u16 = 0xffff;

impl Transport {
    /// Find a virtio device of `device_type` (1 = net, 2 = blk, 8 = scsi). PCI first (the
    /// cloud), then virtio-mmio (the QEMU gates).
    pub fn find(device_type: u32) -> Option<Transport> {
        #[cfg(feature = "pci")]
        if let Some(t) = Self::find_pci(device_type) {
            return Some(t);
        }
        for i in 0..MMIO_COUNT {
            let base = MMIO_BASE + i * MMIO_STRIDE;
            unsafe {
                if r32(base + M_MAGIC) == 0x7472_6976 && r32(base + M_DEVICE_ID) == device_type {
                    return Some(Transport::Mmio(base));
                }
            }
        }
        None
    }

    #[cfg(feature = "pci")]
    fn find_pci(device_type: u32) -> Option<Transport> {
        use crate::mmu::Mmu;
        let ecam = crate::pci::Ecam::open()?;
        // Modern-only device id = 0x1040 + type (what OCI exposes; transitional ids are not
        // claimed here — they would need the legacy I/O-BAR interface).
        let b = ecam.find(VIRTIO_PCI_VENDOR, 0x1040 + device_type as u16)?;
        let (mut common, mut notify, mut device, mut mult) = (None, None, None, 0u32);
        let mmu = Mmu;
        let mut bad = false;
        ecam.caps(b, |p, id| {
            if id != 0x09 {
                return; // only vendor-specific (virtio) capabilities
            }
            let ty = ecam.r8(b, p + 3);
            let bar = ecam.r8(b, p + 4);
            let off = ecam.r32(b, p + 8) as u64;
            let len = ecam.r32(b, p + 12) as u64;
            let want = matches!(ty, 1 | 2 | 4);
            if !want {
                return;
            }
            // BAR + offset must be a real assigned memory BAR; the window must not wrap.
            let Some(base) = ecam.bar(b, bar) else {
                bad = true;
                return;
            };
            let Some(pa) = base.checked_add(off) else {
                bad = true;
                return;
            };
            if len == 0 || pa.checked_add(len).is_none() {
                bad = true;
                return;
            }
            // Map start and end; both must land in the same contiguous window.
            let (Some(va), Some(va_end)) = (mmu.map_mmio(pa as usize), mmu.map_mmio((pa + len - 1) as usize)) else {
                bad = true;
                return;
            };
            if va_end - va != (len - 1) as usize {
                bad = true;
                return;
            }
            match ty {
                1 if len >= 0x38 => common = Some(va),
                2 => {
                    notify = Some(va);
                    mult = ecam.r32(b, p + 16);
                }
                4 => device = Some(va),
                _ => {}
            }
        });
        if bad {
            return None;
        }
        let (common, notify, device) = (common?, notify?, device?);
        // Firmware may leave the function disabled (OCI model: virtio-net command = 0 when
        // UEFI never bound it). Enable memory decode + bus mastering for DMA.
        ecam.set_command(b, ecam.command(b) | 0x2 | 0x4);
        Some(Transport::Pci(PciRegs { common, notify, notify_mult: mult, device, bdf: b }))
    }

    pub fn describe(&self) -> (&'static str, usize, u8, u8, u8) {
        match self {
            Transport::Mmio(b) => ("virtio-mmio", *b, 0, 0, 0),
            #[cfg(feature = "pci")]
            Transport::Pci(p) => ("virtio-pci", p.common, p.bdf.bus, p.bdf.dev, p.bdf.func),
        }
    }

    pub fn set_status(&self, v: u8) {
        unsafe {
            match self {
                Transport::Mmio(b) => w32(b + M_STATUS, v as u32),
                #[cfg(feature = "pci")]
                Transport::Pci(p) => write_volatile((p.common + cc::STATUS) as *mut u8, v),
            }
        }
    }

    pub fn status(&self) -> u8 {
        unsafe {
            match self {
                Transport::Mmio(b) => r32(b + M_STATUS) as u8,
                #[cfg(feature = "pci")]
                Transport::Pci(p) => read_volatile((p.common + cc::STATUS) as *const u8),
            }
        }
    }

    /// Device feature word `sel` (0 = bits 0..31, 1 = bits 32..63).
    pub fn dev_features(&self, sel: u32) -> u32 {
        unsafe {
            match self {
                Transport::Mmio(b) => {
                    w32(b + M_DEV_FEAT_SEL, sel);
                    r32(b + M_DEV_FEAT)
                }
                #[cfg(feature = "pci")]
                Transport::Pci(p) => {
                    w32(p.common + cc::DEV_FEAT_SEL, sel);
                    r32(p.common + cc::DEV_FEAT)
                }
            }
        }
    }

    pub fn set_drv_features(&self, sel: u32, v: u32) {
        unsafe {
            match self {
                Transport::Mmio(b) => {
                    w32(b + M_DRV_FEAT_SEL, sel);
                    w32(b + M_DRV_FEAT, v);
                }
                #[cfg(feature = "pci")]
                Transport::Pci(p) => {
                    w32(p.common + cc::DRV_FEAT_SEL, sel);
                    w32(p.common + cc::DRV_FEAT, v);
                }
            }
        }
    }

    /// Program queue `q` with `size` entries at the given (identity-mapped RAM) addresses
    /// and enable it. False if the device cannot provide `size` entries.
    pub fn setup_queue(&self, q: u16, size: u16, desc: usize, avail: usize, used: usize) -> bool {
        unsafe {
            match self {
                Transport::Mmio(b) => {
                    w32(b + M_QUEUE_SEL, q as u32);
                    w32(b + M_QUEUE_NUM, size as u32);
                    w32(b + M_Q_DESC_LO, desc as u32);
                    w32(b + M_Q_DESC_HI, (desc >> 32) as u32);
                    w32(b + M_Q_DRV_LO, avail as u32);
                    w32(b + M_Q_DRV_HI, (avail >> 32) as u32);
                    w32(b + M_Q_DEV_LO, used as u32);
                    w32(b + M_Q_DEV_HI, (used >> 32) as u32);
                    w32(b + M_QUEUE_READY, 1);
                    true
                }
                #[cfg(feature = "pci")]
                Transport::Pci(p) => {
                    let c = p.common;
                    write_volatile((c + cc::Q_SELECT) as *mut u16, q);
                    let max = read_volatile((c + cc::Q_SIZE) as *const u16);
                    if max == 0 || max < size {
                        return false; // queue absent or too small
                    }
                    write_volatile((c + cc::Q_SIZE) as *mut u16, size);
                    write_volatile((c + cc::Q_MSIX) as *mut u16, NO_VECTOR); // poll mode
                    // 64-bit fields written as two 32-bit halves (permitted by the spec).
                    for (off, a) in [(cc::Q_DESC, desc), (cc::Q_DRIVER, avail), (cc::Q_DEVICE, used)] {
                        w32(c + off, a as u32);
                        w32(c + off + 4, (a >> 32) as u32);
                    }
                    write_volatile((c + cc::Q_ENABLE) as *mut u16, 1);
                    true
                }
            }
        }
    }

    pub fn notify(&self, q: u16) {
        unsafe {
            match self {
                Transport::Mmio(b) => w32(b + M_QUEUE_NOTIFY, q as u32),
                #[cfg(feature = "pci")]
                Transport::Pci(p) => {
                    write_volatile((p.common + cc::Q_SELECT) as *mut u16, q);
                    let off = read_volatile((p.common + cc::Q_NOTIFY_OFF) as *const u16) as usize;
                    // Bounded by the 4 KiB notify window we mapped (device-supplied offset).
                    let a = p.notify + off * p.notify_mult as usize;
                    if a + 2 <= p.notify + 0x1000 {
                        write_volatile(a as *mut u16, q);
                    }
                }
            }
        }
    }

    /// Byte `off` of the device-specific config space (e.g. the virtio-net MAC at 0..6).
    pub fn config_u8(&self, off: usize) -> u8 {
        unsafe {
            match self {
                Transport::Mmio(b) => read_volatile((b + M_CONFIG + off) as *const u8),
                #[cfg(feature = "pci")]
                Transport::Pci(p) => read_volatile((p.device + off) as *const u8),
            }
        }
    }
}
