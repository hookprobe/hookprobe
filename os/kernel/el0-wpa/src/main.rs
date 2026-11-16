//! ADR 0065 step 4g — `el0-wpa`, the resident EL0 WPA security server (operator decision 2026-11-15: the Wi-Fi bus
//! driver and the WPA control plane in two independently restartable EL0 servers; design
//! docs/design/wifi-el0-split.md).
//!
//! The kernel maps this server's image, stack, control page, its PERSISTENT state pages and the key-transfer page, in
//! its own address space. A fault restores the image's writable pages and zeroes the control page — the state pages
//! survive (only a full wipe zeroes them).
//!
//! S2: the 4-way authenticator, the SAE engine, the PMKSA cache and the passphrase / H2E PT live here (moved from
//! el0-wifi, which now holds no key). Their state is a `WpaState` WORKING copy in .bss, saved to the state pages
//! after every command that changes it: written to the inactive of two slots with a check word, then the selector
//! flipped as the last store. A fault part-way through a command leaves the last saved state; the next incarnation
//! loads it (per-station containment: the kernel then drops only the faulting station's handshake). A slot that fails
//! its check answers `ST_STATE_BAD` and the kernel full-wipes.
#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use hal::wifisrvabi::{keymsg, saemsg, H_CMD, H_IN_LEN, H_MAGIC, H_OUT_LEN, H_R0, H_SERVED, H_STATUS, IN_MAX, IN_OFF, OUT_MAX, OUT_OFF, SAE_RND, ST_BAD_CMD, ST_OK, ST_PANIC};
use hal::wifisrvabi::{CMD_KEY_ABORT, CMD_KEY_EAPOL, CMD_KEY_EXPECT, CMD_KEY_START, CMD_KEY_START_SAE, CMD_KEY_TICK, CMD_PMKSA_REMOVE, CMD_SAE_FORGET, CMD_SAE_KEYING, CMD_SAE_RX, CMD_SAE_SETUP};
use hal::wpakeyer::{Direct, Keyer, Out, FRAME_MAX};
use hal::wpasrvabi::*;

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const CTRL: usize = BASE + CTRL_OFF;
const STATE: usize = BASE + STATE_OFF;
const KEYX: usize = BASE + KEYX_OFF;
const SYS_EXIT_USER: u64 = 6;

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((CTRL + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((CTRL + off) as *mut u32, v) }
}
fn io(off: usize, n: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((CTRL + off) as *mut u8, n) }
}
fn input() -> &'static [u8] {
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    &io(IN_OFF, IN_MAX)[..n]
}
fn exit(status: u32, r0: u32) -> ! {
    wr32(H_STATUS, status);
    wr32(H_R0, r0);
    // nothing the kernel sent stays on the shared page once the command is done (key material arrives here in S2)
    io(IN_OFF, IN_MAX).fill(0);
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(ST_PANIC, 0)
}

fn reply(o: &[u8]) -> ! {
    let n = o.len().min(OUT_MAX);
    io(OUT_OFF, n).copy_from_slice(&o[..n]);
    wr32(H_OUT_LEN, n as u32);
    done(ST_OK, 0)
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

// ---- the WPA state, its persistence and the commit protocol ----
struct WpaState {
    keyer: Keyer,
    sae: sae::SaeAp,
    pmksa: sae::PmksaCache,
    pt: Option<sae::PT>,
    pw: [u8; 64],
    pw_len: usize,
    /// S3a: the WPA2-PSK PMK, derived HERE from the passphrase (PBKDF2 over the SSID) or a 64-hex PSK — the kernel
    /// starts a WPA2 4-way with "source 3" and never supplies a PMK.
    psk: [u8; 32],
    psk_set: bool,
    /// S1's substrate test counter (kept: the split selftest still uses it).
    counter: u64,
}
impl WpaState {
    const fn new() -> Self {
        WpaState { keyer: Keyer::new(), sae: sae::SaeAp::new(), pmksa: sae::PmksaCache::new(), pt: None, pw: [0; 64], pw_len: 0, psk: [0; 32], psk_set: false, counter: 0 }
    }
}
/// The working copy (.bss: reset with the image after a fault) and whether it was loaded from the saved state.
static mut WORK: WpaState = WpaState::new();
static mut LOADED: bool = false;
/// Changed by the current command: save it before answering.
static mut DIRTY: bool = false;
/// Test only: a station whose next command faults.
static mut ARMED: Option<[u8; 6]> = None;

const STATE_MAGIC: u64 = u64::from_le_bytes(*b"HQWPST01");
const HDR: usize = 0x40;
const SLOT: usize = (core::mem::size_of::<WpaState>() + 0xFF) & !0xFF;
const _: () = assert!(HDR + 2 * SLOT <= STATE_SIZE);
// header: magic u64 @0, selector u64 @8, check of slot 0 @16, of slot 1 @24
fn hdr(i: usize) -> *mut u64 {
    (STATE + i * 8) as *mut u64
}
fn slot(i: usize) -> *mut u8 {
    (STATE + HDR + i * SLOT) as *mut u8
}
fn check(p: *const u8) -> u64 {
    // FNV-1a over the slot: detects a torn or corrupted slot (the threat is a bug, not an attacker in this space)
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..core::mem::size_of::<WpaState>() {
        h ^= unsafe { read_volatile(p.add(i)) } as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}
fn w() -> &'static mut WpaState {
    unsafe {
        DIRTY = true;
        &mut *core::ptr::addr_of_mut!(WORK)
    }
}
/// Load the saved state into the working copy once per incarnation. False = the saved slot failed its check.
fn load() -> bool {
    unsafe {
        if LOADED {
            return true;
        }
        let magic = read_volatile(hdr(0));
        if magic == 0 {
            LOADED = true; // never saved: the initial state
            return true;
        }
        let sel = (read_volatile(hdr(1)) & 1) as usize;
        if magic != STATE_MAGIC || check(slot(sel)) != read_volatile(hdr(2 + sel)) {
            return false;
        }
        core::ptr::copy_nonoverlapping(slot(sel), core::ptr::addr_of_mut!(WORK) as *mut u8, core::mem::size_of::<WpaState>());
        LOADED = true;
        true
    }
}
/// Save the working copy: the inactive slot, its check, then the selector (the last store commits it).
fn save() {
    unsafe {
        if !DIRTY {
            return;
        }
        let next = 1 - (read_volatile(hdr(1)) & 1) as usize;
        core::ptr::copy_nonoverlapping(core::ptr::addr_of!(WORK) as *const u8, slot(next), core::mem::size_of::<WpaState>());
        write_volatile(hdr(2 + next), check(slot(next)));
        write_volatile(hdr(0), STATE_MAGIC);
        core::arch::asm!("dmb ish");
        write_volatile(hdr(1), next as u64);
        DIRTY = false;
    }
}
/// Every successful answer goes through here: save, then exit.
fn done(status: u32, r0: u32) -> ! {
    save();
    exit(status, r0)
}
fn tab() -> &'static mut sae::SaeAp {
    &mut w().sae
}
fn cache() -> &'static mut sae::PmksaCache {
    &mut w().pmksa
}
/// The station a command is about (the kernel contains a fault to that station).
fn cmd_sta(cmd: u32, inp: &[u8]) -> Option<[u8; 6]> {
    match cmd {
        CMD_KEY_START | CMD_KEY_START_SAE => keymsg::decode_start(inp).map(|s| s.sta),
        CMD_KEY_EXPECT | CMD_KEY_EAPOL | CMD_KEY_ABORT | CMD_SAE_KEYING | CMD_SAE_FORGET | CMD_PMKSA_REMOVE => sta_of(inp),
        CMD_SAE_RX => sta_of(inp.get(6..)?),
        _ => None,
    }
}

/// One authenticator command; the reply is an encoded `Out` (or the expect record).
fn key_cmd(cmd: u32) -> ! {
    let k = &mut w().keyer;
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
    done(ST_OK, 0)
}



// ---- the WPA3-SAE responder + the PMKSA cache (moved from el0-wifi) ----
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
            let st = w();
            hal::wpaauth::wipe(&mut st.pw);
            st.pw[..pl].copy_from_slice(&b[36..36 + pl]);
            st.pw_len = pl;
            // mode 0 = WPA2 only: no SAE; otherwise the H2E PT for this SSID + passphrase
            st.pt = if mode != 0 { sae::derive_pt(&b[3..3 + sl], &b[36..36 + pl], None) } else { None };
            // S3a: the WPA2-PSK PMK, derived here (a 64-hex PSK is the PMK itself; otherwise PBKDF2(passphrase, SSID))
            let pw = &b[36..36 + pl];
            hal::wpaauth::wipe(&mut st.psk);
            st.psk_set = false;
            if pl == 64 && pw.iter().all(|c| c.is_ascii_hexdigit()) {
                let h = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
                for i in 0..32 {
                    st.psk[i] = h(pw[2 * i]) << 4 | h(pw[2 * i + 1]);
                }
                st.psk_set = true;
            } else if pl >= 8 {
                st.psk = hal::wpa::wpa_pmk(pw, &b[3..3 + sl]);
                st.psk_set = true;
            }
            let ok = mode == 0 || st.pt.is_some();
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
            let st = w();
            let e = st.sae.on_frame(now, &ap, &sta, st.pt.as_ref(), &st.pw[..st.pw_len], body, &mut rnd, &mut out);
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
    let k = &mut w().keyer;
    let (Some(mut st), Some(now)) = (keymsg::decode_start(inp), u64_at(inp, keymsg::START_LEN)) else { exit(ST_BAD_CMD, 0) };
    let src = inp.get(keymsg::START_LEN + 8).copied().unwrap_or(0);
    let mut pmkid = [0u8; 16];
    if let Some(p) = inp.get(keymsg::START_LEN + 9..keymsg::START_LEN + 25) {
        pmkid.copy_from_slice(p);
    }
    let pmk = match src {
        1 => tab().pmk_for(&st.sta, now),
        2 => cache().get(&st.sta, &pmkid, now),
        // S3a: WPA2-PSK — this server's own PMK
        3 => {
            let s = w();
            s.psk_set.then_some(s.psk)
        }
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
        None => Out::Failed(hal::wpakeyer::Done { sta: st.sta, akm8: src != 3, cached: src == 2, auth: hal::wpakeyer::Auth::new() }),
    };
    hal::wpaauth::wipe(&mut st.kd.gtk);
    let n = keymsg::encode_out(&r, &frame, &mut o);
    hal::wpaauth::wipe(&mut frame);
    io(OUT_OFF, n).copy_from_slice(&o[..n]);
    hal::wpaauth::wipe(&mut o);
    wr32(H_OUT_LEN, n as u32);
    done(ST_OK, 0)
}


/// Commands served by this incarnation (in .bss: reset by the kernel after a fault, unlike the state pages).
static mut SERVED: u32 = 0;

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
    let cmd = rd32(H_CMD);
    if !load() {
        exit(ST_STATE_BAD, 0);
    }
    // test only: the armed station's next command faults (before it changes anything)
    if let (Some(a), Some(s)) = (unsafe { ARMED }, cmd_sta(cmd, input())) {
        if a == s {
            unsafe { write_volatile(0x8 as *mut u32, 1) };
        }
    }
    match cmd {
        CMD_INIT => exit(ST_OK, 0),
        CMD_STATE_BUMP => {
            let c = &mut w().counter;
            *c = c.wrapping_add(1);
            let v = *c as u32;
            done(ST_OK, v)
        }
        CMD_STATE_READ => exit(ST_OK, unsafe { (*core::ptr::addr_of!(WORK)).counter } as u32),
        CMD_KEY_START | CMD_KEY_EXPECT | CMD_KEY_EAPOL | CMD_KEY_TICK | CMD_KEY_ABORT => key_cmd(cmd),
        CMD_KEY_START_SAE => key_start_sae(),
        CMD_SAE_SETUP | CMD_SAE_RX | CMD_SAE_KEYING | CMD_SAE_FORGET | CMD_PMKSA_REMOVE => sae_cmd(cmd),
        CMD_PMKSA_COUNT => exit(ST_OK, unsafe { (*core::ptr::addr_of!(WORK)).pmksa.len() } as u32),
        CMD_SELFTEST_ARM_FAULT => {
            unsafe { ARMED = sta_of(input()) };
            exit(ST_OK, 0)
        }
        CMD_KEYX_PUT => {
            let b = input();
            let n = b.len().min(0x1000);
            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), KEYX as *mut u8, n) };
            exit(ST_OK, n as u32)
        }
        CMD_SELFTEST_FAULT => unsafe {
            write_volatile(0x8 as *mut u32, 1);
            exit(ST_OK, 0)
        },
        _ => exit(ST_BAD_CMD, 0),
    }
}
