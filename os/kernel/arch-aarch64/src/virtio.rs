//! P5b — minimal virtio-net (virtio-mmio, modern/v2) driver: bring the NIC up,
//! ARP the gateway, and receive one real packet — proving the Packet Engine is
//! fed by real hardware, not synthetic data. Poll-mode (no IRQ). Requires QEMU:
//!   -netdev user,id=n0 -device virtio-net-device,netdev=n0

use crate::mmu;
use core::ptr::{read_volatile, write_volatile};

const MMIO_BASE: usize = 0x0a00_0000;
const MMIO_STRIDE: usize = 0x200;
const MMIO_COUNT: usize = 32;

// virtio-mmio registers
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
const QSZ: usize = 8;
const BUF_SZ: usize = 2048;
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

/// Bring up virtio-net, ARP the gateway (10.0.2.2) from 10.0.2.15, and return
/// the first received packet (payload after the virtio_net_hdr) in `out`.
/// Returns the packet length, or None (no device / rejected / timeout).
pub fn rx_one_packet(out: &mut [u8]) -> Option<usize> {
    let base = find()?;
    unsafe {
        // Reset -> ACKNOWLEDGE -> DRIVER.
        w(base, STATUS, 0);
        w(base, STATUS, S_ACK);
        w(base, STATUS, S_ACK | S_DRIVER);

        // Negotiate MAC (feat 5) + VERSION_1 (feat 32, required for v2 mmio).
        w(base, DEV_FEAT_SEL, 0);
        let dl = r(base, DEV_FEAT);
        w(base, DEV_FEAT_SEL, 1);
        let dh = r(base, DEV_FEAT);
        w(base, DRV_FEAT_SEL, 0);
        w(base, DRV_FEAT, dl & (1 << 5));
        w(base, DRV_FEAT_SEL, 1);
        w(base, DRV_FEAT, dh & 1); // bit 32 = VERSION_1
        w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK);
        if r(base, STATUS) & S_FEAT_OK == 0 {
            crate::_print(format_args!("   features rejected (dl={:#x} dh={:#x})\n", dl, dh));
            return None; // device rejected our features
        }

        // Read the MAC from config space.
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = read_volatile((base + CONFIG + i) as *const u8);
        }
        crate::_print(format_args!(
            "   net up: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ));

        // Allocate split-virtqueue structures (RX=queue 0, TX=queue 1) + buffers.
        let rx_desc = mmu::reserve_region(4096);
        let rx_avail = mmu::reserve_region(4096);
        let rx_used = mmu::reserve_region(4096);
        let tx_desc = mmu::reserve_region(4096);
        let tx_avail = mmu::reserve_region(4096);
        let tx_used = mmu::reserve_region(4096);
        let rx_bufs = mmu::reserve_region(QSZ * BUF_SZ);
        let tx_buf = mmu::reserve_region(BUF_SZ);
        for reg in [rx_desc, rx_avail, rx_used, tx_desc, tx_avail, tx_used] {
            zero(reg, 4096);
        }

        setup_queue(base, 0, rx_desc, rx_avail, rx_used);
        setup_queue(base, 1, tx_desc, tx_avail, tx_used);
        w(base, STATUS, S_ACK | S_DRIVER | S_FEAT_OK | S_DRIVER_OK);

        // Post RX buffers (device-writable), publish avail.idx, notify queue 0.
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

        // Build an ARP request (broadcast) for the gateway, TX on queue 1.
        let p = tx_buf as *mut u8;
        for i in 0..NET_HDR {
            write_volatile(p.add(i), 0);
        }
        let eth = p.add(NET_HDR);
        for i in 0..6 {
            write_volatile(eth.add(i), 0xff); // dst = broadcast
            write_volatile(eth.add(6 + i), mac[i]); // src = our MAC
        }
        write_volatile(eth.add(12), 0x08);
        write_volatile(eth.add(13), 0x06); // ethertype = ARP
        let arp = eth.add(14);
        let hdr = [0x00u8, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]; // eth/IPv4, request
        for i in 0..8 {
            write_volatile(arp.add(i), hdr[i]);
        }
        for i in 0..6 {
            write_volatile(arp.add(8 + i), mac[i]); // sender HW
        }
        let spa = [10u8, 0, 2, 15];
        let tpa = [10u8, 0, 2, 2];
        for i in 0..4 {
            write_volatile(arp.add(14 + i), spa[i]); // sender IP 10.0.2.15
            write_volatile(arp.add(24 + i), tpa[i]); // target IP 10.0.2.2 (gateway)
        }
        for i in 0..6 {
            write_volatile(arp.add(18 + i), 0); // target HW = 0
        }
        let tx_len = NET_HDR + 14 + 28;
        write_volatile(tx_desc as *mut u64, tx_buf as u64);
        write_volatile((tx_desc + 8) as *mut u32, tx_len as u32);
        write_volatile((tx_desc + 12) as *mut u16, 0); // device-readable
        write_volatile((tx_desc + 14) as *mut u16, 0);
        write_volatile((tx_avail + 4) as *mut u16, 0);
        write_volatile((tx_avail + 2) as *mut u16, 1);
        barrier();
        w(base, QUEUE_NOTIFY, 1);
        let _ = tx_used; // TX completion not polled (fire-and-forget for the demo)

        // Poll the RX used ring for the first completed buffer.
        let mut spins: u64 = 0;
        loop {
            barrier();
            let used_idx = read_volatile((rx_used + 2) as *const u16);
            if used_idx != 0 {
                // `id` and `len` come from the DEVICE (untrusted) — bound them
                // before using them to index buffers / size the read, or a
                // hostile NIC forces an out-of-bounds read.
                let id = read_volatile((rx_used + 4) as *const u32) as usize;
                let len = read_volatile((rx_used + 8) as *const u32) as usize;
                if id >= QSZ || len <= NET_HDR || len > BUF_SZ {
                    return None; // reject a malformed device completion
                }
                let pkt = rx_bufs + id * BUF_SZ + NET_HDR;
                let n = (len - NET_HDR).min(out.len());
                for i in 0..n {
                    out[i] = read_volatile((pkt + i) as *const u8);
                }
                return Some(n);
            }
            spins += 1;
            if spins > 30_000_000 {
                return None; // timeout (no reply)
            }
        }
    }
}
