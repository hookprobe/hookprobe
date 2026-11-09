//! P5b — minimal virtio-net driver: bring the NIC up, ARP the gateway, and receive one real
//! packet — proving the Packet Engine is fed by real hardware, not synthetic data.
//! Poll-mode (no IRQ). Transport-agnostic via `virtio_transport`: virtio-mmio v2 on the QEMU
//! gates (`-device virtio-net-device`), virtio-pci modern on the arm64 cloud (OCI A1,
//! feature `pci`).

use crate::mmu;
use crate::virtio_transport::Transport;
use core::ptr::{read_volatile, write_volatile};

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;
const S_FEAT_OK: u8 = 8;

const VIRTQ_DESC_F_WRITE: u16 = 2;
const QSZ: usize = 8;
const BUF_SZ: usize = 2048;
const NET_HDR: usize = 12; // virtio_net_hdr (VERSION_1)

fn zero(base: usize, len: usize) {
    for i in 0..len {
        unsafe { write_volatile((base + i) as *mut u8, 0) };
    }
}
fn barrier() {
    unsafe { core::arch::asm!("dsb sy") };
}

/// Bring up virtio-net, ARP the gateway (10.0.2.2) from 10.0.2.15, and return
/// the first received packet (payload after the virtio_net_hdr) in `out`.
/// Returns the packet length, or None (no device / rejected / timeout).
pub fn rx_one_packet(out: &mut [u8]) -> Option<usize> {
    let t = Transport::find(1)?;
    let (kind, base, bus, dev, func) = t.describe();
    if kind == "virtio-pci" {
        crate::_print(format_args!("   transport: {} {:02x}:{:02x}.{} (common cfg @ VA {:#x})\n", kind, bus, dev, func, base));
    }
    unsafe {
        // Reset -> ACKNOWLEDGE -> DRIVER.
        t.set_status(0);
        t.set_status(S_ACK);
        t.set_status(S_ACK | S_DRIVER);

        // Negotiate MAC (feat 5) + VERSION_1 (feat 32, required for modern transports).
        let dl = t.dev_features(0);
        let dh = t.dev_features(1);
        t.set_drv_features(0, dl & (1 << 5));
        t.set_drv_features(1, dh & 1); // bit 32 = VERSION_1
        t.set_status(S_ACK | S_DRIVER | S_FEAT_OK);
        if t.status() & S_FEAT_OK == 0 {
            crate::_print(format_args!("   features rejected (dl={:#x} dh={:#x})\n", dl, dh));
            return None; // device rejected our features
        }

        // Read the MAC from config space.
        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            *b = t.config_u8(i);
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

        if !t.setup_queue(0, QSZ as u16, rx_desc, rx_avail, rx_used)
            || !t.setup_queue(1, QSZ as u16, tx_desc, tx_avail, tx_used)
        {
            crate::_print(format_args!("   queue setup refused by device\n"));
            return None;
        }
        t.set_status(S_ACK | S_DRIVER | S_FEAT_OK | S_DRIVER_OK);

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
        t.notify(0);

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
        t.notify(1);
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
