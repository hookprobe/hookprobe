// SPDX-License-Identifier: AGPL-3.0-only
//! Modern virtio-pci transport (virtio 1.x §4.1) with split virtqueues (§2.7), polled — enough to prove real I/O
//! on x86_64: a virtio-blk sector read and a virtio-net DHCP DISCOVER → OFFER exchange.
//!
//! Only the capability windows the driver uses are mapped (never whole BARs, and BARs are never re-sized or
//! re-assigned: firmware placement is used as-is). VERSION_1 is mandatory (no legacy transport). No MSI-X yet:
//! completion is polled with a TSC deadline. No virtio-rng here, ever (operator decision 2026-11-22: entropy on
//! x86 comes from RDSEED; virtio-rng exists only in the aarch64 QEMU integration-test profile).

use crate::acpi::Ecam;
use crate::frames::Frames;
use crate::io::rdtsc;
use crate::paging;
use crate::pci::{cfg, r16, r8};
use core::ptr::{read_volatile as rv, write_volatile as wv};
use core::sync::atomic::{fence, Ordering};

fn r32(a: u64) -> u32 {
    unsafe { rv(a as *const u32) }
}
fn w8(a: u64, v: u8) {
    unsafe { wv(a as *mut u8, v) }
}
fn w16(a: u64, v: u16) {
    unsafe { wv(a as *mut u16, v) }
}
fn w32(a: u64, v: u32) {
    unsafe { wv(a as *mut u32, v) }
}

// virtio_pci_common_cfg (§4.1.4.3)
const DFSELECT: u64 = 0x00;
const DF: u64 = 0x04;
const GFSELECT: u64 = 0x08;
const GF: u64 = 0x0C;
const STATUS: u64 = 0x14;
const Q_SELECT: u64 = 0x16;
const Q_SIZE: u64 = 0x18;
const Q_MSIX: u64 = 0x1A;
const Q_ENABLE: u64 = 0x1C;
const Q_NOTIFY_OFF: u64 = 0x1E;
const Q_DESC: u64 = 0x20;
const Q_DRIVER: u64 = 0x28;
const Q_DEVICE: u64 = 0x30;

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;
const S_FEATURES_OK: u8 = 8;
const S_FAILED: u8 = 0x80;

pub const F_VERSION_1: u64 = 1 << 32;
pub const F_NET_MAC: u64 = 1 << 5;

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;
const QSIZE_MAX: u16 = 64;

/// Spin budget for device completions (cycles). Generous: TCG on a loaded host is slow.
const DEADLINE: u64 = 30_000_000_000;

#[derive(Clone, Copy)]
pub struct Func {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

pub struct Transport {
    common: u64,
    notify: u64,
    notify_mul: u32,
    pub device_cfg: u64,
    pub bars_high: bool, // a used capability window lies above 4 GiB (mapped through map_mmio)
}

fn bar_base(e: &Ecam, f: Func, bar: u8) -> Result<u64, &'static str> {
    if bar > 5 {
        return Err("capability names BAR > 5");
    }
    let off = 0x10 + 4 * bar as u16;
    let lo = r32(cfg(e, f.bus, f.dev, f.func, off));
    if lo & 1 != 0 {
        return Err("virtio capability in an I/O BAR");
    }
    let mut base = (lo & !0xF) as u64;
    if (lo >> 1) & 3 == 2 {
        if bar == 5 {
            return Err("64-bit BAR 5");
        }
        base |= (r32(cfg(e, f.bus, f.dev, f.func, off + 4)) as u64) << 32;
    }
    if base == 0 {
        return Err("BAR not assigned by firmware");
    }
    Ok(base)
}

impl Transport {
    /// Locate the common/notify/device capability windows, map them, and enable memory + bus mastering.
    pub fn new(e: &Ecam, f: Func, frames: &mut Frames) -> Result<Transport, &'static str> {
        let c = |off: u16| cfg(e, f.bus, f.dev, f.func, off);
        if r16(c(0x06)) & (1 << 4) == 0 {
            return Err("no capability list");
        }
        let (mut common, mut notify, mut device, mut mul) = (None, None, None, 0u32);
        let mut p = r8(c(0x34)) & 0xFC;
        let mut hops = 0;
        while p >= 0x40 && hops < 48 {
            if r8(c(p as u16)) == 0x09 {
                let ty = r8(c(p as u16 + 3));
                let bar = r8(c(p as u16 + 4));
                let off = r32(c(p as u16 + 8)) as u64;
                let len = r32(c(p as u16 + 12)) as u64;
                let win = (bar, off, len);
                match ty {
                    1 if common.is_none() => common = Some(win),
                    2 if notify.is_none() => {
                        notify = Some(win);
                        mul = r32(c(p as u16 + 16));
                    }
                    4 if device.is_none() => device = Some(win),
                    _ => {}
                }
            }
            p = r8(c(p as u16 + 1)) & 0xFC;
            hops += 1;
        }
        let (common, notify) = (common.ok_or("no common cfg capability")?, notify.ok_or("no notify capability")?);
        let mut high = false;
        let mut map = |(bar, off, len): (u8, u64, u64)| -> Result<u64, &'static str> {
            if len == 0 {
                return Err("empty capability window");
            }
            let a = bar_base(e, f, bar)?.checked_add(off).ok_or("capability window overflows")?;
            high |= a + len > (1 << 32);
            paging::map_mmio(frames, a, len)?;
            Ok(a)
        };
        let t = Transport {
            common: map(common)?,
            notify: map(notify)?,
            notify_mul: mul,
            device_cfg: match device {
                Some(d) => map(d)?,
                None => 0,
            },
            bars_high: false,
        };
        let t = Transport { bars_high: high, ..t };
        // Command register: memory space + bus master (DMA). Interrupt-disable stays as firmware left it.
        let cmd = c(0x04);
        unsafe { wv(cmd as *mut u16, rv(cmd as *const u16) | 0b110) };
        Ok(t)
    }

    fn status(&self) -> u8 {
        unsafe { rv((self.common + STATUS) as *const u8) }
    }

    /// Reset → ACK → DRIVER → feature negotiation (VERSION_1 mandatory) → FEATURES_OK.
    pub fn negotiate(&self, want: u64) -> Result<u64, &'static str> {
        w8(self.common + STATUS, 0);
        let t0 = rdtsc();
        while self.status() != 0 {
            if rdtsc().wrapping_sub(t0) > DEADLINE {
                return Err("device reset did not complete");
            }
        }
        w8(self.common + STATUS, S_ACK);
        w8(self.common + STATUS, S_ACK | S_DRIVER);
        w32(self.common + DFSELECT, 0);
        let lo = r32(self.common + DF) as u64;
        w32(self.common + DFSELECT, 1);
        let dev = lo | (r32(self.common + DF) as u64) << 32;
        if dev & F_VERSION_1 == 0 {
            w8(self.common + STATUS, S_FAILED);
            return Err("device lacks VERSION_1 (legacy-only)");
        }
        let drv = (dev & want) | F_VERSION_1;
        w32(self.common + GFSELECT, 0);
        w32(self.common + GF, drv as u32);
        w32(self.common + GFSELECT, 1);
        w32(self.common + GF, (drv >> 32) as u32);
        w8(self.common + STATUS, S_ACK | S_DRIVER | S_FEATURES_OK);
        if self.status() & S_FEATURES_OK == 0 {
            w8(self.common + STATUS, S_FAILED);
            return Err("device refused our feature set");
        }
        Ok(drv)
    }

    /// Set up split virtqueue `q` (≤ 64 entries) in three zeroed frames; MSI-X vector NO_VECTOR (polled).
    pub fn queue(&self, q: u16, frames: &mut Frames) -> Result<Queue, &'static str> {
        w16(self.common + Q_SELECT, q);
        let max = unsafe { rv((self.common + Q_SIZE) as *const u16) };
        if max == 0 {
            return Err("queue not available");
        }
        let size = max.min(QSIZE_MAX);
        if !size.is_power_of_two() {
            return Err("queue size not a power of two");
        }
        let (desc, avail, used) = (
            frames.alloc().ok_or("no frame")?,
            frames.alloc().ok_or("no frame")?,
            frames.alloc().ok_or("no frame")?,
        );
        w16(self.common + Q_SIZE, size);
        w16(self.common + Q_MSIX, 0xFFFF);
        for (reg, a) in [(Q_DESC, desc), (Q_DRIVER, avail), (Q_DEVICE, used)] {
            w32(self.common + reg, a as u32);
            w32(self.common + reg + 4, (a >> 32) as u32);
        }
        let noff = unsafe { rv((self.common + Q_NOTIFY_OFF) as *const u16) } as u64;
        w16(self.common + Q_ENABLE, 1);
        Ok(Queue { q, size, desc, avail, used, notify: self.notify + noff * self.notify_mul as u64, next_desc: 0, avail_idx: 0, last_used: 0 })
    }

    pub fn driver_ok(&self) -> Result<(), &'static str> {
        w8(self.common + STATUS, S_ACK | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);
        if self.status() & S_FAILED != 0 {
            return Err("device set FAILED");
        }
        Ok(())
    }
}

pub struct Queue {
    q: u16,
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    notify: u64,
    next_desc: u16,
    avail_idx: u16,
    last_used: u16,
}

impl Queue {
    /// Publish one descriptor chain of (address, length, device-writable) buffers and notify the device.
    pub fn submit(&mut self, bufs: &[(u64, u32, bool)]) -> Result<u16, &'static str> {
        if bufs.is_empty() || bufs.len() > self.size as usize {
            return Err("bad chain length");
        }
        let head = self.next_desc;
        for (i, &(addr, len, write)) in bufs.iter().enumerate() {
            let d = (self.next_desc % self.size) as u64;
            let last = i + 1 == bufs.len();
            let next = (self.next_desc + 1) % self.size;
            let base = self.desc + d * 16;
            unsafe {
                wv(base as *mut u64, addr);
                wv((base + 8) as *mut u32, len);
                wv((base + 12) as *mut u16, if write { DESC_WRITE } else { 0 } | if last { 0 } else { DESC_NEXT });
                wv((base + 14) as *mut u16, if last { 0 } else { next });
            }
            self.next_desc = next;
        }
        let slot = (self.avail_idx % self.size) as u64;
        w16(self.avail + 4 + slot * 2, head % self.size);
        fence(Ordering::SeqCst); // descriptors + ring entry visible before the index moves
        self.avail_idx = self.avail_idx.wrapping_add(1);
        w16(self.avail + 2, self.avail_idx);
        fence(Ordering::SeqCst);
        w16(self.notify, self.q);
        Ok(head % self.size)
    }

    /// Next used element (descriptor head id, bytes written), or None at the deadline.
    pub fn wait_used(&mut self, deadline: u64) -> Option<(u32, u32)> {
        let t0 = rdtsc();
        loop {
            let idx = unsafe { rv((self.used + 2) as *const u16) };
            if idx != self.last_used {
                fence(Ordering::SeqCst);
                let e = self.used + 4 + (self.last_used % self.size) as u64 * 8;
                self.last_used = self.last_used.wrapping_add(1);
                return Some((r32(e), r32(e + 4)));
            }
            if rdtsc().wrapping_sub(t0) > deadline {
                return None;
            }
            core::hint::spin_loop();
        }
    }
}

// ------------------------------------------------------------------ virtio-blk

pub struct BlkResult {
    pub capacity_sectors: u64,
    pub sector0: [u8; 64],
    pub high_bars: bool,
}

/// Bring up virtio-blk and READ sector 0 (VIRTIO_BLK_T_IN).
pub fn blk_read_sector0(e: &Ecam, f: Func, frames: &mut Frames) -> Result<BlkResult, &'static str> {
    let t = Transport::new(e, f, frames)?;
    t.negotiate(0)?;
    let mut q = t.queue(0, frames)?;
    t.driver_ok()?;
    let capacity = if t.device_cfg != 0 { unsafe { rv(t.device_cfg as *const u64) } } else { 0 };
    let hdr = frames.alloc().ok_or("no frame")?;
    let data = frames.alloc().ok_or("no frame")?;
    unsafe {
        wv(hdr as *mut u32, 0); // type IN (read)
        wv((hdr + 8) as *mut u64, 0); // sector 0
        wv((hdr + 16) as *mut u8, 0xFF); // status: the device must overwrite it
    }
    q.submit(&[(hdr, 16, false), (data, 512, true), (hdr + 16, 1, true)])?;
    q.wait_used(DEADLINE).ok_or("virtio-blk: no completion")?;
    let st = unsafe { rv((hdr + 16) as *const u8) };
    if st != 0 {
        return Err("virtio-blk: request status not OK");
    }
    let mut s0 = [0u8; 64];
    for (i, b) in s0.iter_mut().enumerate() {
        *b = unsafe { rv((data + i as u64) as *const u8) };
    }
    Ok(BlkResult { capacity_sectors: capacity, sector0: s0, high_bars: t.bars_high })
}

// ------------------------------------------------------------------ virtio-net

pub struct NetResult {
    pub mac: [u8; 6],
    pub offered: [u8; 4],
    pub server: [u8; 4],
    pub high_bars: bool,
}

const NET_HDR: usize = 12; // struct virtio_net_hdr with num_buffers (always present with VERSION_1)

fn csum16(b: &[u8]) -> u16 {
    let mut s = 0u32;
    for c in b.chunks(2) {
        s += u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0));
    }
    while s > 0xFFFF {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

/// Build a DHCPDISCOVER (broadcast) behind a zeroed virtio-net header; returns its length.
fn dhcp_discover(buf: &mut [u8], mac: [u8; 6], xid: u32) -> usize {
    let opts: &[u8] = &[53, 1, 1, 55, 3, 1, 3, 6, 255]; // DISCOVER; ask for mask, router, DNS
    let bootp_len = 240 + opts.len();
    let udp_len = 8 + bootp_len;
    let ip_len = 20 + udp_len;
    let total = NET_HDR + 14 + ip_len;
    buf[..total].fill(0);
    let eth = &mut buf[NET_HDR..];
    eth[0..6].fill(0xFF);
    eth[6..12].copy_from_slice(&mac);
    eth[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut eth[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 17; // UDP
    ip[16..20].fill(0xFF); // dst 255.255.255.255 (src 0.0.0.0)
    let c = csum16(&ip[..20]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let udp = &mut ip[20..];
    udp[0..2].copy_from_slice(&68u16.to_be_bytes());
    udp[2..4].copy_from_slice(&67u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // checksum 0: optional over IPv4
    let b = &mut udp[8..];
    b[0] = 1; // BOOTREQUEST
    b[1] = 1; // Ethernet
    b[2] = 6;
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast reply
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    b[240..240 + opts.len()].copy_from_slice(opts);
    total
}

/// Parse one received frame (after the virtio-net header) as a DHCPOFFER for `xid`.
fn parse_offer(f: &[u8], xid: u32) -> Option<([u8; 4], [u8; 4])> {
    if f.len() < 14 + 20 + 8 + 240 || f[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &f[14..];
    let ihl = ((ip[0] & 0xF) as usize) * 4;
    if ip[0] >> 4 != 4 || ip[9] != 17 || ihl < 20 || ip.len() < ihl + 8 + 240 {
        return None;
    }
    let udp = &ip[ihl..];
    if udp[0..2] != 67u16.to_be_bytes() || udp[2..4] != 68u16.to_be_bytes() {
        return None;
    }
    let b = &udp[8..];
    if b[0] != 2 || b[4..8] != xid.to_be_bytes() || b[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }
    let (mut ty, mut server) = (0u8, [0u8; 4]);
    let mut i = 240;
    while i < b.len() && b[i] != 255 {
        if b[i] == 0 {
            i += 1;
            continue;
        }
        let (code, len) = (b[i], *b.get(i + 1)? as usize);
        let v = b.get(i + 2..i + 2 + len)?;
        match code {
            53 if len == 1 => ty = v[0],
            54 if len == 4 => server.copy_from_slice(v),
            _ => {}
        }
        i += 2 + len;
    }
    (ty == 2).then(|| ([b[16], b[17], b[18], b[19]], server))
}

/// Bring up virtio-net (RX queue 0, TX queue 1), send a DHCPDISCOVER, and wait for the matching DHCPOFFER.
pub fn net_dhcp_probe(e: &Ecam, f: Func, frames: &mut Frames, xid: u32) -> Result<NetResult, &'static str> {
    let t = Transport::new(e, f, frames)?;
    let feats = t.negotiate(F_NET_MAC)?;
    let mut rx = t.queue(0, frames)?;
    let mut tx = t.queue(1, frames)?;
    t.driver_ok()?;
    let mut mac = [0x52, 0x54, 0x00, 0x58, 0x32, 0x01]; // locally administered fallback
    if feats & F_NET_MAC != 0 && t.device_cfg != 0 {
        for (i, m) in mac.iter_mut().enumerate() {
            *m = unsafe { rv((t.device_cfg + i as u64) as *const u8) };
        }
    }
    let mut rx_bufs = [0u64; 8];
    for b in rx_bufs.iter_mut() {
        *b = frames.alloc().ok_or("no frame")?;
        rx.submit(&[(*b, 2048, true)])?;
    }
    let txb = frames.alloc().ok_or("no frame")?;
    let len = dhcp_discover(unsafe { core::slice::from_raw_parts_mut(txb as *mut u8, 4096) }, mac, xid);
    tx.submit(&[(txb, len as u32, false)])?;
    tx.wait_used(DEADLINE).ok_or("virtio-net: TX not completed")?;
    for _ in 0..rx_bufs.len() {
        let (id, n) = rx.wait_used(DEADLINE).ok_or("virtio-net: no DHCPOFFER received")?;
        let buf = *rx_bufs.get(id as usize).ok_or("virtio-net: bad used id")?;
        let n = (n as usize).min(2048);
        if n <= NET_HDR {
            continue;
        }
        let frame = unsafe { core::slice::from_raw_parts((buf + NET_HDR as u64) as *const u8, n - NET_HDR) };
        if let Some((offered, server)) = parse_offer(frame, xid) {
            return Ok(NetResult { mac, offered, server, high_bars: t.bars_high });
        }
    }
    Err("virtio-net: frames received, none a matching DHCPOFFER")
}
