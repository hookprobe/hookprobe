//! M3.1 — minimal virtio-blk (virtio-mmio, modern/v2) block device behind
//! `hal::BlockDev`. This is the QEMU **write path with cross-restart persistence**
//! (a file-backed `-drive`) that replaces the volatile `RamDisk` for the M3
//! persistence proof — the real `brcm,bcm2712-sdhci` eMMC driver (`emmc.rs`,
//! `cfg(cm5)`) is the metal slot-in behind this SAME trait (Gate R). Requires QEMU:
//!   -drive file=<img>,format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0
//!
//! Poll-mode, single request virtqueue (queue 0), one 512-B transfer per call —
//! deliberately tiny (the FS/OTA logic lives above `BlockDev`, not here). The
//! `len`/`id`/`status` the DEVICE writes back are UNTRUSTED and bounds-checked
//! before use, exactly as the virtio-net driver treats a hostile NIC.

use crate::mmu;
use core::ptr::{read_volatile, write_volatile};
use hal::{BlockDev, BlockErr};

const MMIO_BASE: usize = 0x0a00_0000;
const MMIO_STRIDE: usize = 0x200;
const MMIO_COUNT: usize = 32;

// virtio-mmio registers (same layout as the net driver).
const MAGIC: usize = 0x000;
const DEVICE_ID: usize = 0x008;
const DEV_FEAT: usize = 0x010;
const DEV_FEAT_SEL: usize = 0x014;
const DRV_FEAT: usize = 0x020;
const DRV_FEAT_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM: usize = 0x038;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const STATUS: usize = 0x070;
const Q_DESC_LO: usize = 0x080;
const Q_DESC_HI: usize = 0x084;
const Q_DRV_LO: usize = 0x090;
const Q_DRV_HI: usize = 0x094;
const Q_DEV_LO: usize = 0x0a0;
const Q_DEV_HI: usize = 0x0a4;
const CONFIG: usize = 0x100;

const S_ACK: u32 = 1;
const S_DRIVER: u32 = 2;
const S_DRIVER_OK: u32 = 4;
const S_FEAT_OK: u32 = 8;

const VIRTIO_ID_BLOCK: u32 = 2;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTIO_BLK_T_IN: u32 = 0; // read (device -> memory)
const VIRTIO_BLK_T_OUT: u32 = 1; // write (memory -> device)
const VIRTIO_BLK_S_OK: u8 = 0;

const QSZ: usize = 8;

unsafe fn r(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}
unsafe fn w(base: usize, off: usize, v: u32) {
    write_volatile((base + off) as *mut u32, v);
}
fn barrier() {
    unsafe { core::arch::asm!("dsb sy") };
}

fn find() -> Option<usize> {
    for i in 0..MMIO_COUNT {
        let base = MMIO_BASE + i * MMIO_STRIDE;
        unsafe {
            if r(base, MAGIC) == 0x7472_6976 && r(base, DEVICE_ID) == VIRTIO_ID_BLOCK {
                return Some(base);
            }
        }
    }
    None
}

/// A brought-up virtio-blk device. Read always; write behind `p15-write`, and —
/// as the trait's independent gate 2 — the write path refuses LBA 0 (the MBR)
/// unconditionally, so a store-layer bug can never overwrite the partition table.
pub struct VirtioBlk {
    base: usize,
    sectors: u64,
    desc: usize,
    avail: usize,
    used: usize,
    hdr: usize,
    data: usize,
    status: usize,
    avail_idx: u16,
    used_seen: u16,
}

impl VirtioBlk {
    /// Discover + bring up the first virtio-blk device. Returns None if QEMU
    /// attached no `-drive`/`virtio-blk-device` (so a diskless boot skips cleanly).
    pub fn open() -> Option<VirtioBlk> {
        let base = find()?;
        unsafe {
            // Reset -> ACKNOWLEDGE -> DRIVER.
            w(base, STATUS, 0);
            w(base, STATUS, S_ACK);
            w(base, STATUS, S_ACK | S_DRIVER);

            // Negotiate ONLY VERSION_1 (feat bit 32) — required for v2 mmio; we
            // need no blk-specific features for single-sector PIO-style transfers.
            w(base, DEV_FEAT_SEL, 1);
            let dh = r(base, DEV_FEAT);
            w(base, DRV_FEAT_SEL, 0);
            w(base, DRV_FEAT, 0);
            w(base, DRV_FEAT_SEL, 1);
            w(base, DRV_FEAT, dh & 1); // bit 32 = VERSION_1
            w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK);
            if r(base, STATUS) & S_FEAT_OK == 0 {
                return None; // device rejected our feature set
            }

            // Capacity (config offset 0) is a u64 in 512-byte sectors.
            let cap_lo = read_volatile((base + CONFIG) as *const u32) as u64;
            let cap_hi = read_volatile((base + CONFIG + 4) as *const u32) as u64;
            let sectors = (cap_hi << 32) | cap_lo;

            // Split-virtqueue structures + the (reused) request buffers.
            let desc = mmu::reserve_region(4096);
            let avail = mmu::reserve_region(4096);
            let used = mmu::reserve_region(4096);
            let hdr = mmu::reserve_region(512);
            let data = mmu::reserve_region(512);
            let status = mmu::reserve_region(512);
            if desc == 0 || avail == 0 || used == 0 || hdr == 0 || data == 0 || status == 0 {
                return None; // OOM
            }

            w(base, QUEUE_SEL, 0);
            w(base, QUEUE_NUM, QSZ as u32);
            w(base, Q_DESC_LO, desc as u32);
            w(base, Q_DESC_HI, (desc >> 32) as u32);
            w(base, Q_DRV_LO, avail as u32);
            w(base, Q_DRV_HI, (avail >> 32) as u32);
            w(base, Q_DEV_LO, used as u32);
            w(base, Q_DEV_HI, (used >> 32) as u32);
            w(base, QUEUE_READY, 1);
            w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK | S_DRIVER_OK);

            Some(VirtioBlk {
                base,
                sectors,
                desc,
                avail,
                used,
                hdr,
                data,
                status,
                avail_idx: 0,
                used_seen: 0,
            })
        }
    }

    /// Submit one 3-descriptor blk request (header RO, data, status WO) and poll
    /// the used ring for completion. Returns the device status byte.
    unsafe fn submit(&mut self, req_type: u32, lba: u64, data_dev_writable: bool) -> Option<u8> {
        // Header: type u32, reserved u32, sector u64 (all little-endian).
        write_volatile(self.hdr as *mut u32, req_type);
        write_volatile((self.hdr + 4) as *mut u32, 0);
        write_volatile((self.hdr + 8) as *mut u64, lba);
        write_volatile(self.status as *mut u8, 0xff); // poison; device writes OK/ERR

        // desc0 = header (device-readable), chained to desc1.
        write_volatile(self.desc as *mut u64, self.hdr as u64);
        write_volatile((self.desc + 8) as *mut u32, 16);
        write_volatile((self.desc + 12) as *mut u16, VIRTQ_DESC_F_NEXT);
        write_volatile((self.desc + 14) as *mut u16, 1);
        // desc1 = 512-byte data; device-writable for a READ, readable for a WRITE.
        let d1_flags = VIRTQ_DESC_F_NEXT
            | if data_dev_writable {
                VIRTQ_DESC_F_WRITE
            } else {
                0
            };
        write_volatile((self.desc + 16) as *mut u64, self.data as u64);
        write_volatile((self.desc + 24) as *mut u32, 512);
        write_volatile((self.desc + 28) as *mut u16, d1_flags);
        write_volatile((self.desc + 30) as *mut u16, 2);
        // desc2 = status byte (device-writable), end of chain.
        write_volatile((self.desc + 32) as *mut u64, self.status as u64);
        write_volatile((self.desc + 40) as *mut u32, 1);
        write_volatile((self.desc + 44) as *mut u16, VIRTQ_DESC_F_WRITE);
        write_volatile((self.desc + 46) as *mut u16, 0);

        // Publish the head descriptor (index 0) into the avail ring, bump idx.
        let slot = (self.avail_idx as usize) % QSZ;
        write_volatile((self.avail + 4 + slot * 2) as *mut u16, 0u16);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        write_volatile((self.avail + 2) as *mut u16, self.avail_idx);
        barrier();
        w(self.base, QUEUE_NOTIFY, 0);

        // Poll the used ring for the completion of THIS request.
        let mut spins: u64 = 0;
        loop {
            barrier();
            let uidx = read_volatile((self.used + 2) as *const u16);
            if uidx != self.used_seen {
                self.used_seen = uidx;
                // The device-written `id` is untrusted — bound it before use.
                let ue = self.used + 4 + ((uidx.wrapping_sub(1) as usize) % QSZ) * 8;
                let id = read_volatile(ue as *const u32) as usize;
                if id >= QSZ {
                    return None;
                }
                return Some(read_volatile(self.status as *const u8));
            }
            spins += 1;
            if spins > 30_000_000 {
                return None; // timeout
            }
        }
    }
}

impl BlockDev for VirtioBlk {
    fn block_count(&self) -> u64 {
        self.sectors
    }

    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        if lba >= self.sectors {
            return Err(BlockErr::OutOfRange);
        }
        // `submit` mutates ring bookkeeping; the trait read is &self, so take a
        // short-lived mutable view of the fixed fields (single-threaded boot path).
        let me = self as *const VirtioBlk as *mut VirtioBlk;
        unsafe {
            match (*me).submit(VIRTIO_BLK_T_IN, lba, true) {
                Some(VIRTIO_BLK_S_OK) => {
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = read_volatile(((*me).data + i) as *const u8);
                    }
                    Ok(())
                }
                _ => Err(BlockErr::Io),
            }
        }
    }

    /// Write behind `p15-write` only. Gate 2 (independent of the store-layer
    /// allowlist): LBA 0 is refused unconditionally so the MBR / partition table
    /// can never be overwritten by a store-layer bug. The eMMC arm-window is the
    /// metal analogue of this refusal.
    #[cfg(feature = "p15-write")]
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        if lba == 0 {
            return Err(BlockErr::WriteRefused); // gate 2: never the MBR
        }
        if lba >= self.sectors {
            return Err(BlockErr::OutOfRange);
        }
        unsafe {
            for (i, b) in buf.iter().enumerate() {
                write_volatile((self.data + i) as *mut u8, *b);
            }
            match self.submit(VIRTIO_BLK_T_OUT, lba, false) {
                Some(VIRTIO_BLK_S_OK) => Ok(()),
                _ => Err(BlockErr::Io),
            }
        }
    }
}
