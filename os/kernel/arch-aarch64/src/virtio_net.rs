//! M4.1 — persistent, pollable virtio-net (virtio-mmio, modern/v2) driver.
//!
//! `virtio.rs::rx_one_packet` is a one-shot: it resets the NIC, sends a single
//! ARP, and returns exactly one frame. To drive a real protocol handshake
//! (DHCP DISCOVER→OFFER→REQUEST→ACK, then DNS/SNTP) the stack needs a NIC it can
//! `rx()`/`tx()` repeatedly across many polls. This module is that: bring the
//! device up ONCE (`open`), then pump frames with RX-buffer recycling.
//!
//! Poll-mode (no IRQ), same register plumbing as `virtio.rs`. `id`/`len` fields
//! written by the DEVICE are UNTRUSTED — every one is bounds-checked before it
//! indexes a buffer or sizes a copy (a hostile NIC must not force an OOB read).
//! The IPS verdict gate lives ONE layer up (`netcfg::VirtioPhy`), so this driver
//! stays a dumb, bounded transport; nothing here decides PASS/DROP.
//!
//! QEMU (`-netdev user`) proven; the real RP1 GEM / RTL8111 datapath at line rate
//! is metal (Gate R). This is deliberately NOT wired into the default/prod TCB —
//! it is only built + used under the `netsvc` feature's M4.1 selftest.

use crate::mmu;
use core::ptr::{read_volatile, write_volatile};

const MMIO_BASE: usize = 0x0a00_0000;
const MMIO_STRIDE: usize = 0x200;
const MMIO_COUNT: usize = 32;

// virtio-mmio registers (subset — same map as virtio.rs).
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

const VIRTQ_DESC_F_WRITE: u16 = 2;
const QSZ: usize = 64; // ring depth per queue (power of two; each queue struct fits its 4 KiB page up to 256)
const BUF_SZ: usize = 2048; // per-buffer capacity
const NET_HDR: usize = 12; // virtio_net_hdr (VERSION_1)

unsafe fn r(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}
unsafe fn w(base: usize, off: usize, v: u32) {
    write_volatile((base + off) as *mut u32, v);
}
fn zero(base: usize, len: usize) {
    for i in 0..len {
        unsafe { write_volatile((base + i) as *mut u8, 0) };
    }
}
fn barrier() {
    unsafe { core::arch::asm!("dsb sy") };
}

fn find() -> Option<usize> {
    for i in 0..MMIO_COUNT {
        let base = MMIO_BASE + i * MMIO_STRIDE;
        unsafe {
            if r(base, MAGIC) == 0x7472_6976 && r(base, DEVICE_ID) == 1 {
                return Some(base);
            }
        }
    }
    None
}

unsafe fn setup_queue(base: usize, q: u32, desc: usize, avail: usize, used: usize) {
    w(base, QUEUE_SEL, q);
    w(base, QUEUE_NUM, QSZ as u32);
    w(base, Q_DESC_LO, desc as u32);
    w(base, Q_DESC_HI, (desc >> 32) as u32);
    w(base, Q_DRV_LO, avail as u32);
    w(base, Q_DRV_HI, (avail >> 32) as u32);
    w(base, Q_DEV_LO, used as u32);
    w(base, Q_DEV_HI, (used >> 32) as u32);
    w(base, QUEUE_READY, 1);
}

/// A persistent virtio-net device: RX queue 0, TX queue 1, poll-mode.
pub struct VirtioNet {
    base: usize,
    mac: [u8; 6],
    // RX split-virtqueue. (rx_desc is written once in `open`; the descriptors are
    // static thereafter — only the avail/used rings + buffers are touched at runtime.)
    rx_avail: usize,
    rx_used: usize,
    rx_bufs: usize,
    rx_used_seen: u16, // our consumer cursor into the RX used ring
    rx_avail_idx: u16, // running avail.idx (buffers we've offered the device)
    // TX split-virtqueue.
    tx_desc: usize,
    tx_avail: usize,
    tx_used: usize,
    tx_bufs: usize,
    tx_next: u16, // round-robin TX buffer/descriptor slot
    tx_avail_idx: u16,
}

impl VirtioNet {
    /// Find + reset + negotiate + set up both queues + post all RX buffers.
    /// `None` if no virtio-net device is present or it rejects our features.
    pub fn open() -> Option<VirtioNet> {
        let base = find()?;
        unsafe {
            w(base, STATUS, 0);
            w(base, STATUS, S_ACK);
            w(base, STATUS, S_ACK | S_DRIVER);

            // Negotiate MAC (feat 5) + VERSION_1 (feat 32).
            w(base, DEV_FEAT_SEL, 0);
            let dl = r(base, DEV_FEAT);
            w(base, DEV_FEAT_SEL, 1);
            let dh = r(base, DEV_FEAT);
            w(base, DRV_FEAT_SEL, 0);
            w(base, DRV_FEAT, dl & (1 << 5));
            w(base, DRV_FEAT_SEL, 1);
            w(base, DRV_FEAT, dh & 1);
            w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK);
            if r(base, STATUS) & S_FEAT_OK == 0 {
                return None;
            }

            let mut mac = [0u8; 6];
            for (i, b) in mac.iter_mut().enumerate() {
                *b = read_volatile((base + CONFIG + i) as *const u8);
            }

            let rx_desc = mmu::reserve_region(4096);
            let rx_avail = mmu::reserve_region(4096);
            let rx_used = mmu::reserve_region(4096);
            let tx_desc = mmu::reserve_region(4096);
            let tx_avail = mmu::reserve_region(4096);
            let tx_used = mmu::reserve_region(4096);
            let rx_bufs = mmu::reserve_region(QSZ * BUF_SZ);
            let tx_bufs = mmu::reserve_region(QSZ * BUF_SZ);
            for reg in [rx_desc, rx_avail, rx_used, tx_desc, tx_avail, tx_used] {
                zero(reg, 4096);
            }

            setup_queue(base, 0, rx_desc, rx_avail, rx_used);
            setup_queue(base, 1, tx_desc, tx_avail, tx_used);
            w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK | S_DRIVER_OK);

            // Post all RX buffers device-writable; publish avail.idx = QSZ; notify.
            for i in 0..QSZ {
                let d = rx_desc + i * 16;
                write_volatile(d as *mut u64, (rx_bufs + i * BUF_SZ) as u64);
                write_volatile((d + 8) as *mut u32, BUF_SZ as u32);
                write_volatile((d + 12) as *mut u16, VIRTQ_DESC_F_WRITE);
                write_volatile((d + 14) as *mut u16, 0);
                write_volatile((rx_avail + 4 + i * 2) as *mut u16, i as u16);
            }
            write_volatile((rx_avail + 2) as *mut u16, QSZ as u16);
            barrier();
            w(base, QUEUE_NOTIFY, 0);

            Some(VirtioNet {
                base,
                mac,
                rx_avail,
                rx_used,
                rx_bufs,
                rx_used_seen: 0,
                rx_avail_idx: QSZ as u16,
                tx_desc,
                tx_avail,
                tx_used,
                tx_bufs,
                tx_next: 0,
                tx_avail_idx: 0,
            })
        }
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Non-blocking RX: return the next received frame payload (after the
    /// virtio_net_hdr) in `out`, recycling its buffer back to the device.
    /// `None` if the used ring has advanced no further than we've consumed.
    pub fn rx(&mut self, out: &mut [u8]) -> Option<usize> {
        unsafe {
            barrier();
            let used_idx = read_volatile((self.rx_used + 2) as *const u16);
            if used_idx == self.rx_used_seen {
                return None; // nothing new
            }
            let ring_pos = (self.rx_used_seen as usize) % QSZ;
            // virtq_used_elem { u32 id; u32 len; } at rx_used + 4 + ring_pos*8.
            let id = read_volatile((self.rx_used + 4 + ring_pos * 8) as *const u32) as usize;
            let len = read_volatile((self.rx_used + 8 + ring_pos * 8) as *const u32) as usize;
            // DEVICE-supplied — bound before use.
            if id >= QSZ || len <= NET_HDR || len > BUF_SZ {
                // Malformed completion: still advance our cursor + recycle so we
                // don't wedge, but deliver nothing.
                self.rx_used_seen = self.rx_used_seen.wrapping_add(1);
                self.recycle(id.min(QSZ - 1));
                return None;
            }
            let pkt = self.rx_bufs + id * BUF_SZ + NET_HDR;
            let n = (len - NET_HDR).min(out.len());
            for (i, b) in out.iter_mut().enumerate().take(n) {
                *b = read_volatile((pkt + i) as *const u8);
            }
            self.rx_used_seen = self.rx_used_seen.wrapping_add(1);
            self.recycle(id);
            Some(n)
        }
    }

    /// Re-offer RX buffer `id` to the device (descriptor is unchanged; we only
    /// re-add it to the avail ring and bump avail.idx).
    unsafe fn recycle(&mut self, id: usize) {
        let avail_pos = (self.rx_avail_idx as usize) % QSZ;
        write_volatile((self.rx_avail + 4 + avail_pos * 2) as *mut u16, id as u16);
        self.rx_avail_idx = self.rx_avail_idx.wrapping_add(1);
        write_volatile((self.rx_avail + 2) as *mut u16, self.rx_avail_idx);
        barrier();
        w(self.base, QUEUE_NOTIFY, 0);
    }

    /// TX one Ethernet frame (a virtio_net_hdr of zeros is prepended), round-robin over QSZ
    /// buffers. Returns false if oversize OR the ring is full: a slot is reused only after the
    /// device has COMPLETED it (used.idx), so a burst can never overwrite a frame still in flight
    /// (it used to be fire-and-forget — safe for a couple of frames, silent corruption for a
    /// streamed HTTP response). The caller retries a refused frame on its next pass.
    pub fn tx(&mut self, frame: &[u8]) -> bool {
        if frame.len() + NET_HDR > BUF_SZ {
            return false;
        }
        let used_idx = unsafe {
            barrier();
            read_volatile((self.tx_used + 2) as *const u16)
        };
        if self.tx_next.wrapping_sub(used_idx) as usize >= QSZ {
            return false; // every slot still owned by the device
        }
        let slot = (self.tx_next as usize) % QSZ;
        self.tx_next = self.tx_next.wrapping_add(1);
        unsafe {
            let buf = self.tx_bufs + slot * BUF_SZ;
            for i in 0..NET_HDR {
                write_volatile((buf + i) as *mut u8, 0);
            }
            for (i, &b) in frame.iter().enumerate() {
                write_volatile((buf + NET_HDR + i) as *mut u8, b);
            }
            let d = self.tx_desc + slot * 16;
            write_volatile(d as *mut u64, buf as u64);
            write_volatile((d + 8) as *mut u32, (NET_HDR + frame.len()) as u32);
            write_volatile((d + 12) as *mut u16, 0); // device-readable
            write_volatile((d + 14) as *mut u16, 0);
            let avail_pos = (self.tx_avail_idx as usize) % QSZ;
            write_volatile((self.tx_avail + 4 + avail_pos * 2) as *mut u16, slot as u16);
            self.tx_avail_idx = self.tx_avail_idx.wrapping_add(1);
            write_volatile((self.tx_avail + 2) as *mut u16, self.tx_avail_idx);
            barrier();
            w(self.base, QUEUE_NOTIFY, 1);
        }
        true
    }
}
