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
use hal::wifisrvabi::keymsg;
use hal::wpakeyer::{Direct, Keyer, Out, FRAME_MAX};
use hal::wifisrvabi::saemsg;
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
fn sta_of(b: &[u8]) -> Option<[u8; 6]> {
    let mut s = [0u8; 6];
    s.copy_from_slice(b.get(..6)?);
    Some(s)
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    let mut r = [0u8; 8];
    r.copy_from_slice(b.get(o..o + 8)?);
    Some(u64::from_le_bytes(r))
}

/// ADR 0065 step 3b: the 4-way authenticator, RESIDENT here with its keys (operator D3, 2026-11-15).
static mut KEYER: Keyer = Keyer::new();

/// One authenticator command; the reply is an encoded `Out` (or the expect record).
fn key_cmd(cmd: u32) -> ! {
    let k = unsafe { &mut *core::ptr::addr_of_mut!(KEYER) };
    let inp = input();
    let mut frame = [0u8; FRAME_MAX];
    let mut o = [0u8; keymsg::OUT_MAX];
    let r = match cmd {
        CMD_KEY_START => {
            let (Some(mut st), Some(now)) = (keymsg::decode_start(inp), u64_at(inp, keymsg::START_LEN)) else { exit(ST_BAD_CMD, 0) };
            let r = k.start(st, now, &mut frame);
            hal::wpaauth::wipe(&mut st.pmk);
            hal::wpaauth::wipe(&mut st.kd.gtk);
            r
        }
        CMD_KEY_EXPECT => {
            let Some(sta) = sta_of(inp) else { exit(ST_BAD_CMD, 0) };
            let e = k.expect(&sta);
            o[0] = e.is_some() as u8;
            o[1] = e.is_some_and(|x| x.0) as u8;
            o[2..10].copy_from_slice(&e.map_or(0, |x| x.1).to_le_bytes());
            reply(&o[..10])
        }
        CMD_KEY_EAPOL => {
            let (Some(sta), Some(now)) = (sta_of(inp), u64_at(inp, 6)) else { exit(ST_BAD_CMD, 0) };
            k.on_eapol(&sta, &inp[14..], now, &mut Direct, &mut frame)
        }
        CMD_KEY_TICK => {
            let Some(now) = u64_at(inp, 0) else { exit(ST_BAD_CMD, 0) };
            k.tick(now, &mut frame)
        }
        CMD_KEY_ABORT => {
            let Some(sta) = sta_of(inp) else { exit(ST_BAD_CMD, 0) };
            k.abort(&sta);
            Out::None
        }
        _ => exit(ST_BAD_CMD, 0),
    };
    let n = keymsg::encode_out(&r, &frame, &mut o);
    hal::wpaauth::wipe(&mut frame);
    // a Keyed reply carries the TK: the kernel installs it and scrubs the OUT area (2A / D3 wipe discipline)
    let n2 = n.min(OUT_MAX);
    io(OUT_OFF, n2).copy_from_slice(&o[..n2]);
    hal::wpaauth::wipe(&mut o);
    wr32(H_OUT_LEN, n2 as u32);
    exit(ST_OK, 0)
}

// ---- ADR 0065 steps 3c / 3d: the WPA3-SAE responder + the PMKSA cache, with every SAE secret, live HERE ----
static mut SAE_TAB: sae::SaeAp = sae::SaeAp::new();
static mut PMKSA: sae::PmksaCache = sae::PmksaCache::new();
static mut SAE_PT: Option<sae::PT> = None;
static mut PW: [u8; 64] = [0; 64];
static mut PW_LEN: usize = 0;

fn tab() -> &'static mut sae::SaeAp {
    unsafe { &mut *core::ptr::addr_of_mut!(SAE_TAB) }
}
fn cache() -> &'static mut sae::PmksaCache {
    unsafe { &mut *core::ptr::addr_of_mut!(PMKSA) }
}

fn sae_cmd(cmd: u32) -> ! {
    let inp = input();
    let mut o = [0u8; saemsg::RX_OUT_LEN];
    match cmd {
        CMD_SAE_SETUP => {
            // mode ‖ clear ‖ ssid_len ‖ ssid[32] ‖ pw_len ‖ pw[64]
            let Some(b) = inp.get(..1 + 1 + 1 + 32 + 1 + 64) else { exit(ST_BAD_CMD, 0) };
            let (mode, clear) = (b[0], b[1] != 0);
            let sl = (b[2] as usize).min(32);
            let pl = (b[35] as usize).min(64);
            if clear {
                cache().clear();
            }
            tab().forget_all();
            unsafe {
                hal::wpaauth::wipe(&mut *core::ptr::addr_of_mut!(PW));
                (&mut *core::ptr::addr_of_mut!(PW))[..pl].copy_from_slice(&b[36..36 + pl]);
                PW_LEN = pl;
                // mode 0 = WPA2 only: no SAE; otherwise the H2E PT for this SSID + passphrase
                SAE_PT = if mode != 0 { sae::derive_pt(&b[3..3 + sl], &b[36..36 + pl], None) } else { None };
            }
            let ok = mode == 0 || unsafe { (*core::ptr::addr_of!(SAE_PT)).is_some() };
            o[0] = ok as u8;
            reply(&o[..1])
        }
        CMD_SAE_RX => {
            let pre = 6 + 6 + 8 + SAE_RND;
            if inp.len() < pre {
                exit(ST_BAD_CMD, 0)
            }
            let (Some(ap), Some(sta), Some(now)) = (sta_of(inp), sta_of(&inp[6..]), u64_at(inp, 12)) else { exit(ST_BAD_CMD, 0) };
            let rnd_pool = &inp[20..20 + SAE_RND];
            let mut used = 0usize;
            let mut rnd = || {
                if used + 32 > SAE_RND {
                    return None; // fail-closed: the frame is dropped, never answered with weak randomness
                }
                let mut r = [0u8; 32];
                r.copy_from_slice(&rnd_pool[used..used + 32]);
                used += 32;
                Some(r)
            };
            let body = &inp[pre..];
            let mut out = [None, None];
            let pw_len = unsafe { PW_LEN };
            let e = unsafe {
                tab().on_frame(now, &ap, &sta, (*core::ptr::addr_of!(SAE_PT)).as_ref(), &(&*core::ptr::addr_of!(PW))[..pw_len], body, &mut rnd, &mut out)
            };
            let mut pmkid = [0u8; 16];
            let (ev, status) = match e {
                sae::Event::None => (0, 0),
                sae::Event::Dropped(_) => (1, 0),
                sae::Event::Committed => (2, 0),
                sae::Event::Accepted => {
                    cache().add_accepted(tab(), &sta, now); // a later PMKSA-caching reconnect
                    pmkid = tab().pmkid_for(&sta, now).unwrap_or([0; 16]);
                    (3, 0)
                }
                sae::Event::Refused(st) => (4, st),
            };
            let f0 = out[0].as_ref().map_or(&[][..], |f| &f.body[..f.len]);
            let f1 = out[1].as_ref().map_or(&[][..], |f| &f.body[..f.len]);
            let n = out.iter().flatten().count();
            let k = saemsg::encode_rx(ev, status, &[f0, f1], n, &pmkid, &mut o);
            reply(&o[..k])
        }
        CMD_SAE_KEYING => {
            let (Some(sta), Some(now)) = (sta_of(inp), u64_at(inp, 6)) else { exit(ST_BAD_CMD, 0) };
            let Some(offers) = inp.get(14).copied() else { exit(ST_BAD_CMD, 0) };
            let Some(rsn) = saemsg::decode_rsn(&inp[15..]) else { exit(ST_BAD_CMD, 0) };
            let fresh = tab().pmk_for(&sta, now).is_some();
            let c = cache();
            let how = hal::rsnassoc::decide(rsn.as_ref(), offers, fresh, &mut |p| c.get(&sta, p, now).is_some());
            let (code, idx) = saemsg::keying_code(&how);
            let (dc, age) = tab().diag(&sta, now);
            o[0] = code;
            o[1] = idx;
            o[2] = dc;
            o[3..11].copy_from_slice(&age.to_le_bytes());
            o[11] = fresh as u8; // the Legacy rule: a just-completed SAE keys as SAE
            reply(&o[..12])
        }
        CMD_SAE_FORGET => {
            let (Some(sta), Some(now)) = (sta_of(inp), u64_at(inp, 6)) else { exit(ST_BAD_CMD, 0) };
            let r = match inp.get(14).copied() {
                Some(0) => {
                    // a leave of the station's earlier attempt, processed after its new SAE Accepted, must not undo it
                    let (st, age) = tab().diag(&sta, now);
                    if hal::rsnassoc::leave_predates_sae(st == sae::SD_ACCEPTED, age) {
                        false
                    } else {
                        tab().forget_at(&sta, now);
                        true
                    }
                }
                Some(1) => {
                    tab().forget(&sta);
                    true
                }
                _ => {
                    tab().forget_all();
                    true
                }
            };
            o[0] = r as u8;
            reply(&o[..1])
        }
        CMD_PMKSA_REMOVE => {
            let Some(sta) = sta_of(inp) else { exit(ST_BAD_CMD, 0) };
            if inp.get(6).copied() == Some(1) {
                cache().clear();
            } else {
                cache().remove(&sta);
            }
            reply(&o[..0])
        }
        _ => exit(ST_BAD_CMD, 0),
    }
}

/// KEY_START with the PMK from this server's own SAE table (1) or PMKSA cache (2): the SAE PMK never leaves EL0.
fn key_start_sae() -> ! {
    let inp = input();
    let k = unsafe { &mut *core::ptr::addr_of_mut!(KEYER) };
    let (Some(mut st), Some(now)) = (keymsg::decode_start(inp), u64_at(inp, keymsg::START_LEN)) else { exit(ST_BAD_CMD, 0) };
    let src = inp.get(keymsg::START_LEN + 8).copied().unwrap_or(0);
    let mut pmkid = [0u8; 16];
    if let Some(p) = inp.get(keymsg::START_LEN + 9..keymsg::START_LEN + 25) {
        pmkid.copy_from_slice(p);
    }
    let pmk = match src {
        1 => tab().pmk_for(&st.sta, now),
        2 => cache().get(&st.sta, &pmkid, now),
        _ => None,
    };
    let mut frame = [0u8; FRAME_MAX];
    let mut o = [0u8; keymsg::OUT_MAX];
    let r = match pmk {
        Some(mut p) => {
            st.pmk = p;
            hal::wpaauth::wipe(&mut p);
            let r = k.start(st, now, &mut frame);
            hal::wpaauth::wipe(&mut st.pmk);
            r
        }
        // no PMK here (expired / never accepted): a handshake that cannot start
        None => Out::Failed(hal::wpakeyer::Done { sta: st.sta, akm8: true, cached: src == 2, auth: hal::wpakeyer::Auth::new() }),
    };
    hal::wpaauth::wipe(&mut st.kd.gtk);
    let n = keymsg::encode_out(&r, &frame, &mut o);
    hal::wpaauth::wipe(&mut frame);
    io(OUT_OFF, n).copy_from_slice(&o[..n]);
    hal::wpaauth::wipe(&mut o);
    wr32(H_OUT_LEN, n as u32);
    exit(ST_OK, 0)
}

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
        CMD_KEY_START | CMD_KEY_EXPECT | CMD_KEY_EAPOL | CMD_KEY_TICK | CMD_KEY_ABORT => key_cmd(rd32(H_CMD)),
        CMD_KEY_START_SAE => key_start_sae(),
        CMD_BUS_PROBE => bus_probe(),
        CMD_RX_READ => rx_read(),
        CMD_TX_DATA => tx_data(),
        CMD_TX_CTL => tx_ctl(),
        CMD_SAE_SETUP | CMD_SAE_RX | CMD_SAE_KEYING | CMD_SAE_FORGET | CMD_PMKSA_REMOVE => sae_cmd(rd32(H_CMD)),
        CMD_SELFTEST_BAD_RING => {
            // a hostile driver: claim 1000 frames pending in the RX ring
            let r = ring_at(RX_OFF);
            r[0..4].copy_from_slice(&1000u32.to_le_bytes());
            exit(ST_OK, 0)
        }
        CMD_SELFTEST_FAULT => unsafe {
            write_volatile(0x8 as *mut u32, 1);
            exit(ST_OK, 0)
        },
        _ => exit(ST_BAD_CMD, 0),
    }
}
