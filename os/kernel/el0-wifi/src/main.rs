//! ADR 0065 — `el0-wifi`, the resident EL0 Wi-Fi driver server.
//!
//! Step 2: the substrate. The server is RESIDENT: the kernel maps its image, stack, control page, the device page it
//! was granted, and the two frame rings ONCE; each command re-enters `_start`, and the server's `.data` / `.bss`
//! persist between commands until a fault makes the kernel reset them. The device in this step is a fake (one RAM
//! page, `hal::wifisrvabi::FDEV_*`); step 4 puts the CYW43455's SDHCI registers there.
#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use hal::el0ring as ring;
use hal::wifisrvabi::rxmsg;
use hal::wifisrvabi::txmsg;
use hal::wifisrvabi::ctlmsg;
use hal::wifisrvabi::*;

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const CTRL: usize = BASE + CTRL_OFF;
const DEV: usize = BASE + DEV_OFF;
const SYS_EXIT_USER: u64 = 6;

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((CTRL + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((CTRL + off) as *mut u32, v) }
}
fn exit(status: u32, r0: u32) -> ! {
    wr32(H_STATUS, status);
    wr32(H_R0, r0);
    // nothing the kernel sent (a PMK, the key data) stays on the shared page once the command is done
    hal::wpaauth::wipe(io(IN_OFF, IN_MAX));
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(ST_PANIC, 0)
}

fn io(off: usize, n: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((CTRL + off) as *mut u8, n) }
}
fn input() -> &'static [u8] {
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    &io(IN_OFF, IN_MAX)[..n]
}
fn reply(o: &[u8]) -> ! {
    let n = o.len().min(OUT_MAX);
    io(OUT_OFF, n).copy_from_slice(&o[..n]);
    wr32(H_OUT_LEN, n as u32);
    exit(ST_OK, 0)
}

// ADR 0065 step 4g (S2, operator decision 2026-11-15): the 4-way authenticator, the SAE engine and the PMKSA cache
// moved to el0-wpa, the separate WPA security server. This bus server holds no key material.

/// ADR 0065 step 4a: read the granted device page's identity registers (no read side effects; the kernel compares).
fn bus_probe() -> ! {
    let mut o = [0u8; PROBE_REGS.len() * 4];
    for (i, off) in PROBE_REGS.iter().enumerate() {
        let v = unsafe { read_volatile((DEV + off) as *const u32) };
        o[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    reply(&o)
}

/// ADR 0065 step 4b-2b: the SDHCI registers through this server's Device grant.
struct UMmio;
impl hal::sdio::Mmio for UMmio {
    fn r8(&self, o: usize) -> u8 {
        unsafe { read_volatile((DEV + o) as *const u8) }
    }
    fn r16(&self, o: usize) -> u16 {
        unsafe { read_volatile((DEV + o) as *const u16) }
    }
    fn r32(&self, o: usize) -> u32 {
        unsafe { read_volatile((DEV + o) as *const u32) }
    }
    fn w8(&self, o: usize, v: u8) {
        unsafe { write_volatile((DEV + o) as *mut u8, v) }
    }
    fn w16(&self, o: usize, v: u16) {
        unsafe { write_volatile((DEV + o) as *mut u16, v) }
    }
    fn w32(&self, o: usize, v: u32) {
        unsafe { write_volatile((DEV + o) as *mut u32, v) }
    }
}
static mut BUS: hal::sdio::Bus<UMmio> = hal::sdio::Bus::new(UMmio);

/// Read ONE SDPCM frame off F2 (the same `Bus::read_frame` the kernel ran in-line): one poll. The mailbox interrupt
/// is the kernel's (`HostInt`); a dry budget is the kernel's loop.
fn rx_read() -> ! {
    let Some((sdb, max_dry, skip, block, cap)) = rxmsg::decode_in(input()) else { exit(ST_BAD_CMD, 0) };
    let mut buf = [0u8; 2048];
    let cap = cap.clamp(hal::sdio::FIRSTREAD, buf.len());
    let bus = unsafe { &mut *core::ptr::addr_of_mut!(BUS) };
    // ONE poll, never a wait: EL0 has no counter access on the CM5 (CNTKCTL_EL1.EL0PCTEN is not granted; metal
    // 2026-11-15, k4d: the 1 ms delay read CNTFRQ/CNTPCT here and every wait trapped, EC 0x18). The kernel loops and
    // delays between polls.
    let _ = max_dry;
    let r = bus.read_frame(sdb, &mut buf[..cap], 0, skip, block, None, &mut || {});
    let mut o = [0u8; OUT_MAX];
    let n = rxmsg::encode_out(&r, &buf[..cap], bus.blk_diag, &mut o);
    io(OUT_OFF, n).copy_from_slice(&o[..n]);
    wr32(H_OUT_LEN, n as u32);
    exit_lean(0)
}

/// The hot-path exit: no key material crosses on the frame commands, so only the input bytes used are cleared (not
/// the 2 KiB IN scrub of `exit`, which the keying commands need).
fn exit_lean(r0: u32) -> ! {
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    io(IN_OFF, n).fill(0);
    wr32(H_STATUS, ST_OK);
    wr32(H_R0, r0);
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

/// Step 4c: build ONE SDPCM data frame with the sequence the kernel assigned and write it to F2 (the kernel keeps
/// the credit window and the flow-control mask, and advances the sequence only on `Sent`).
fn tx_data() -> ! {
    let Some((seq, ifidx, big, eth)) = txmsg::decode_in(input()) else { exit(ST_BAD_CMD, 0) };
    let mut f = [0u8; hal::sdio::DATA_TX_BUF];
    let n = hal::sdio::data_frame(seq, ifidx, eth, &mut f);
    let bus = unsafe { &mut *core::ptr::addr_of_mut!(BUS) };
    let w = bus.write_frame(&f, n, big);
    exit_lean(txmsg::encode_r0(w))
}

/// Commands served by this incarnation (in .bss: survives between calls, reset by the kernel after a fault).
static mut SERVED: u32 = 0;

fn ring_at(off: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((BASE + off) as *mut u8, ring::RING_BYTES) }
}
fn dev16(off: usize) -> u16 {
    unsafe { read_volatile((DEV + off) as *const u16) }
}
fn set_dev16(off: usize, v: u16) {
    unsafe { write_volatile((DEV + off) as *mut u16, v) }
}
fn dev(off: usize, n: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((DEV + off) as *mut u8, n) }
}

/// One poll of the fake device: its received frame (if any) into the RX ring; one TX-ring frame (if any) out to it.
fn poll() -> u32 {
    let mut moved = 0u32;
    let n = dev16(FDEV_RX_LEN) as usize;
    if n > 0 && n <= FDEV_FRAME_MAX && ring::push(ring_at(RX_OFF), &dev(FDEV_RX_DATA, n)[..]) {
        set_dev16(FDEV_RX_LEN, 0);
        moved += 1;
    }
    let mut buf = [0u8; FDEV_FRAME_MAX];
    if let ring::Pop::Frame(k) = ring::pop(ring_at(TX_OFF), &mut buf) {
        dev(FDEV_TX_DATA, k).copy_from_slice(&buf[..k]);
        set_dev16(FDEV_TX_LEN, k as u16);
        moved += 1;
    }
    moved
}

/// Step 4d: build ONE control request with the kernel's sequence and request id and write it to F2 — one byte-mode
/// CMD53, exactly as the driver's control path does (the kernel matches the reply).
fn tx_ctl() -> ! {
    let Some((seq, ifidx, cmd, flags, reqid, reply_len, payload)) = ctlmsg::decode_in(input()) else { exit(ST_BAD_CMD, 0) };
    let mut f = [0u8; hal::bcdc::FRAME_MAX];
    let n = hal::bcdc::request(seq, cmd, flags, reqid, ifidx, payload, reply_len, &mut f);
    let padded = (n + 3) & !3;
    let bus = unsafe { &mut *core::ptr::addr_of_mut!(BUS) };
    let ok = bus.cmd53_write(2, hal::sdio::F2_ADDR, &f[..padded]);
    exit_lean(if ok { 1 } else { 4 })
}

/// S3c: install a key from the key-transfer page (read-only here; el0-wpa wrote it) as a WLC_SET_KEY control
/// request — the only way a key reaches the chip. The record must be the one the kernel asked for (station + key
/// index), else nothing is sent. Every local copy is wiped before exit; the kernel zeroes the page.
fn key_install() -> ! {
    use hal::wpasrvabi::keyx;
    let Some((seq, ifidx, reqid, slot, ea, index)) = keyx::decode_install(input()) else { exit(ST_BAD_CMD, 0) };
    let mut raw = [0u8; keyx::SLOT_SIZE];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = unsafe { read_volatile((BASE + KEYX_OFF + slot as usize * keyx::SLOT_SIZE + i) as *const u8) };
    }
    let rec = keyx::decode(&raw);
    hal::wpaauth::wipe(&mut raw);
    let Some(mut rec) = rec.filter(|r| r.ea == ea && r.index == index) else { exit_lean(5) };
    let mut payload = hal::bcdc::wsec_key(rec.index, &rec.key[..rec.klen as usize], rec.algo, rec.flags, &rec.ea);
    hal::wpaauth::wipe(&mut rec.key);
    let mut f = [0u8; hal::bcdc::FRAME_MAX];
    let n = hal::bcdc::request(seq, hal::bcdc::WLC_SET_KEY, hal::bcdc::SET, reqid, ifidx, &payload, 0, &mut f);
    hal::wpaauth::wipe(&mut payload);
    let bus = unsafe { &mut *core::ptr::addr_of_mut!(BUS) };
    let ok = bus.cmd53_write(2, hal::sdio::F2_ADDR, &f[..(n + 3) & !3]);
    hal::wpaauth::wipe(&mut f);
    exit_lean(if ok { 1 } else { 4 })
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_CMD, 0);
    }
    let served = unsafe {
        SERVED += 1;
        SERVED
    };
    wr32(H_SERVED, served);
    match rd32(H_CMD) {
        CMD_INIT => exit(ST_OK, 0),
        CMD_POLL => exit(ST_OK, poll()),
        CMD_BUS_PROBE => bus_probe(),
        CMD_RX_READ => rx_read(),
        // S1: the key-transfer page el0-wpa writes is readable here (S3: a key record on its way to the chip)
        CMD_KEYX_PEEK => {
            let mut o = [0u8; 16];
            for (i, b) in o.iter_mut().enumerate() {
                *b = unsafe { read_volatile((BASE + KEYX_OFF + i) as *const u8) };
            }
            reply(&o)
        }
        CMD_TX_DATA => tx_data(),
        CMD_TX_CTL => tx_ctl(),
        hal::wpasrvabi::CMD_KEY_INSTALL => key_install(),
        CMD_SELFTEST_BAD_RING => {
            // a hostile driver: claim 1000 frames pending in the RX ring
            let r = ring_at(RX_OFF);
            r[0..4].copy_from_slice(&1000u32.to_le_bytes());
            exit(ST_OK, 0)
        }
        // it is mapped read-only here: this write must fault (the kernel counts it and resets this server only)
        CMD_SELFTEST_KEYX_WRITE => unsafe {
            write_volatile((BASE + KEYX_OFF) as *mut u8, 0xEE);
            exit(ST_OK, 0)
        },
        // S4 bench isolation probe: read 8 bytes at a VA (another server's pages must fault here)
        CMD_INJECT_READ_VA => {
            let b = input();
            if b.len() < 8 {
                exit(ST_BAD_CMD, 0)
            }
            let va = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as usize;
            let v = unsafe { read_volatile(va as *const u64) };
            reply(&v.to_le_bytes())
        }
        // S4 bench injection: arm a stuck CMD53 (one shot — this incarnation dies of it)
        CMD_INJECT_CMD53_STALL => unsafe {
            (*core::ptr::addr_of_mut!(BUS)).stall_next_cmd53 = true;
            exit(ST_OK, 0)
        },
        CMD_SELFTEST_FAULT => unsafe {
            write_volatile(0x8 as *mut u32, 1);
            exit(ST_OK, 0)
        },
        _ => exit(ST_BAD_CMD, 0),
    }
}
