// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0065: the ABI of `el0-wifi`, the resident EL0 Wi-Fi driver server.
//!
//! Window (one per platform): the image, its stack, one control page, the device mapping, then the two frame rings
//! ([`crate::el0ring`]). Step 2 (this ABI's first user) drives a FAKE device in QEMU: one RAM page with the register
//! layout below; the real CYW43455 / SDHCI mapping replaces it in step 4.

pub const BASE_QEMU: usize = 0xBC00_0000;
/// After el0-hsh (ends 0x1_4032_A000), inside the CM5 GB5 user window (ends 0x1_4040_0000).
pub const BASE_CM5: usize = 0x1_4034_0000;
pub const IMAGE_MAX: usize = 0x2_0000; // 128 KiB
pub const STACK_OFF: usize = 0x2_0000;
pub const STACK_SIZE: usize = 0x1_0000; // 64 KiB: the SAE curve arithmetic (step 3c), as el0-lansvc
/// One page: the command block below.
pub const CTRL_OFF: usize = 0x3_0000;
/// One page: the device the kernel granted (step 2: the fake device; step 4: the SDHCI registers).
pub const DEV_OFF: usize = 0x3_1000;
/// Driver -> kernel frames (received from the device).
pub const RX_OFF: usize = 0x3_8000;
/// Kernel -> driver frames (to send to the device).
pub const TX_OFF: usize = RX_OFF + crate::el0ring::RING_BYTES + 0x1000;
/// ADR 0065 S1: the key-transfer page, mapped READ-ONLY here (RW in el0-wpa, `crate::wpasrvabi::KEYX_OFF`).
pub const KEYX_OFF: usize = TX_OFF + crate::el0ring::RING_BYTES;
/// The window's end, relative to the base (must stay inside the platform's user window).
pub const WINDOW_END: usize = KEYX_OFF + 0x1000;

// ---- control page ----
pub const H_MAGIC: usize = 0; // u32 "HQWF"
pub const H_CMD: usize = 4;
pub const H_STATUS: usize = 8;
/// u32 the server returns (CMD_POLL: frames moved; CMD_INIT: 0).
pub const H_R0: usize = 12;
/// u32 the server keeps in its own .bss and reports: how many commands this incarnation has served (proves the
/// server is RESIDENT — its memory persists between calls until a fault resets it).
pub const H_SERVED: usize = 16;
pub const MAGIC: u32 = u32::from_le_bytes(*b"HQWF");

/// Bring the device up (step 2: nothing to do but answer).
pub const CMD_INIT: u32 = 1;
/// Move frames: device RX -> the RX ring, the TX ring -> device TX.
pub const CMD_POLL: u32 = 2;
/// Test only: misbehave as a hostile driver would — leave the RX ring inconsistent (the kernel must refuse it).
pub const CMD_SELFTEST_BAD_RING: u32 = 98;
/// S1: OUT = the first 16 bytes of the key-transfer page (proves el0-wifi can read what el0-wpa put there).
pub const CMD_KEYX_PEEK: u32 = 34;
/// Step 4e: IN = backplane address (u32 LE) + up to [`BP_WRITE_MAX`] bytes; el0-wifi writes them through the F1
/// window (`hal::sdio::Bus::backplane_write`). R0 = 1 written / 4 the write failed. The firmware / NVRAM download.
pub const CMD_BP_WRITE: u32 = 36;
/// Data bytes per [`CMD_BP_WRITE`]: the input page less the address, whole 64-B blocks.
pub const BP_WRITE_MAX: usize = (IN_MAX - 4) / 64 * 64;
/// Step 4e-2: one register operation of a firmware reload (chip probe, EROM walk, core reset, clocks), run by
/// el0-wifi over its own grant. IN = op (u8), function (u8), 2 pad, address (u32 LE), value (u32 LE) = 12 bytes.
/// OUT = ok (u8: 1 / 0) + 3 pad + value read (u32 LE). Ops: [`REG_CMD52_R`] … [`REG_WINDOW`].
pub const CMD_BP_REG: u32 = 37;
pub const REG_CMD52_R: u8 = 0;
pub const REG_CMD52_W: u8 = 1;
pub const REG_BP_R32: u8 = 2;
pub const REG_BP_W32: u8 = 3;
pub const REG_WINDOW: u8 = 4;
/// Step 4e-3a: one SD command (card enumeration: CMD5 / CMD3 / CMD7). Function byte = flags (bit 0 CRC + index
/// check, bit 1 data phase); address = the argument; value = index (low 16 bits) | response kind (high 16 bits).
/// OUT value = the response.
pub const REG_CMD: u8 = 5;
/// Step 4e-3b: an SDHCI host-controller register read / write (host reset, card presence, power, clock, bus width).
/// Function byte = width in bytes (1, 2 or 4); address = the register offset inside the SDHCI window (< 0x1000,
/// aligned to the width); value = what is written.
pub const REG_HOST_R: u8 = 6;
pub const REG_HOST_W: u8 = 7;
/// Encode one [`CMD_BP_REG`] request.
pub fn bp_reg_in(op: u8, fnum: u8, addr: u32, val: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = op;
    b[1] = fnum;
    b[4..8].copy_from_slice(&addr.to_le_bytes());
    b[8..12].copy_from_slice(&val.to_le_bytes());
    b
}
/// Decode a [`CMD_BP_REG`] request: (op, function, address, value); None = malformed or an unknown op / function.
pub fn bp_reg_decode(i: &[u8]) -> Option<(u8, u8, u32, u32)> {
    if i.len() != 12 || i[0] > REG_HOST_W {
        return None;
    }
    let addr = u32::from_le_bytes([i[4], i[5], i[6], i[7]]);
    let ok = match i[0] {
        REG_CMD => i[1] <= 3,
        // a host register: width 1 / 2 / 4, aligned, inside the 4 KiB SDHCI window (the server can touch nothing else)
        REG_HOST_R | REG_HOST_W => matches!(i[1], 1 | 2 | 4) && addr < 0x1000 && addr.is_multiple_of(i[1] as u32),
        _ => i[1] <= 2,
    };
    if !ok {
        return None;
    }
    Some((i[0], i[1], u32::from_le_bytes([i[4], i[5], i[6], i[7]]), u32::from_le_bytes([i[8], i[9], i[10], i[11]])))
}
/// Test only: WRITE the key-transfer page — it is read-only here, so this must fault.
pub const CMD_SELFTEST_KEYX_WRITE: u32 = 97;
/// Test only: fault on purpose (the supervisor's restart path).
pub const CMD_SELFTEST_FAULT: u32 = 99;
/// Bench fault injection (ADR 0065 S4, kernel feature `wifi-inject` only): the next CMD53 read this server issues
/// stalls forever (an injected CMD53 timeout) — the kernel's budget faults it and restarts it.
pub const CMD_INJECT_CMD53_STALL: u32 = 96;
/// Bench isolation probe (ADR 0065 S4, `wifi-inject` only): IN = a u64 VA; the bus server reads 8 bytes there and
/// replies them. Used on el0-wpa's image and state pages, which must FAULT (not mapped in the bus server's space).
pub const CMD_INJECT_READ_VA: u32 = 95;

pub const ST_OK: u32 = 0;
pub const ST_BAD_CMD: u32 = 2;
pub const ST_PANIC: u32 = 0xffff_ffff;

// ---- step 2 fake device (one page) ----
/// u16: length of the frame the device has received (0 = none); the driver clears it after taking the frame.
pub const FDEV_RX_LEN: usize = 0;
pub const FDEV_RX_DATA: usize = 0x10;
/// u16: length of the last frame the driver sent to the device.
pub const FDEV_TX_LEN: usize = 0x800;
pub const FDEV_TX_DATA: usize = 0x810;
/// The largest frame the fake device holds per direction.
pub const FDEV_FRAME_MAX: usize = 0x7f0;

// ---- step 3b: the control page's message areas + the authenticator commands ----
/// u32: bytes of input at IN_OFF.
pub const H_IN_LEN: usize = 20;
/// u32: bytes of output at OUT_OFF.
pub const H_OUT_LEN: usize = 24;
pub const IN_OFF: usize = 0x40;
pub const IN_MAX: usize = 0x7C0;
pub const OUT_OFF: usize = 0x800;
pub const OUT_MAX: usize = 0x800;

/// IN = [`keymsg::encode_start`] ‖ now_ms u64. OUT = [`keymsg::encode_out`] (M1).
pub const CMD_KEY_START: u32 = 10;
/// IN = sta 6. OUT = found u8 ‖ secure u8 ‖ replay u64.
pub const CMD_KEY_EXPECT: u32 = 11;
/// IN = sta 6 ‖ now_ms u64 ‖ the classified 802.1X frame. OUT = [`keymsg::encode_out`].
pub const CMD_KEY_EAPOL: u32 = 12;
/// IN = now_ms u64. OUT = [`keymsg::encode_out`].
pub const CMD_KEY_TICK: u32 = 13;
/// IN = sta 6. OUT = nothing.
pub const CMD_KEY_ABORT: u32 = 14;

/// The authenticator messages (pure; the kernel and el0-wifi both use them).
pub mod keymsg {
    use crate::wpakeyer::{Auth, Done, KeyData, Out, Start};

    pub const START_LEN: usize = 6 + 6 + 32 + 1 + 17 + 32 + 1 + 40 + 16 + 1 + 31;
    pub const DONE_LEN: usize = 6 + 1 + 1 + AUTH_LEN;
    const AUTH_LEN: usize = 6 + 2 + 4 * 3 + 8;
    /// The largest encoded Out: kind ‖ len u16 ‖ (frame | Done ‖ tk).
    pub const OUT_MAX: usize = 3 + crate::wpakeyer::FRAME_MAX;

    pub fn encode_start(s: &Start, o: &mut [u8]) -> usize {
        let mut i = 0;
        let mut put = |b: &[u8]| {
            o[i..i + b.len()].copy_from_slice(b);
            i += b.len();
        };
        put(&s.sta);
        put(&s.aa);
        put(&s.pmk);
        put(&[s.akm8 as u8]);
        put(&[s.pmkid.is_some() as u8]);
        put(&s.pmkid.unwrap_or([0; 16]));
        put(&s.anonce);
        put(&[s.kd.rsne_len.min(40) as u8]);
        put(&s.kd.rsne);
        put(&s.kd.gtk);
        put(&[s.kd.gtk_keyid]);
        put(&[s.kd.igtk_kde.is_some() as u8]);
        put(&s.kd.igtk_kde.unwrap_or([0; 30]));
        START_LEN
    }
    pub fn decode_start(b: &[u8]) -> Option<Start> {
        let b = b.get(..START_LEN)?;
        let mut i = 0;
        let mut take = |n: usize| {
            let r = &b[i..i + n];
            i += n;
            r
        };
        let mut s = Start { sta: [0; 6], aa: [0; 6], pmk: [0; 32], akm8: false, pmkid: None, anonce: [0; 32],
            kd: KeyData { rsne: [0; 40], rsne_len: 0, gtk: [0; 16], gtk_keyid: 0, igtk_kde: None } };
        s.sta.copy_from_slice(take(6));
        s.aa.copy_from_slice(take(6));
        s.pmk.copy_from_slice(take(32));
        s.akm8 = take(1)[0] != 0;
        let has_pmkid = take(1)[0] != 0;
        let mut p = [0u8; 16];
        p.copy_from_slice(take(16));
        s.pmkid = has_pmkid.then_some(p);
        s.anonce.copy_from_slice(take(32));
        s.kd.rsne_len = (take(1)[0] as usize).min(40);
        s.kd.rsne.copy_from_slice(take(40));
        s.kd.gtk.copy_from_slice(take(16));
        s.kd.gtk_keyid = take(1)[0];
        let has_igtk = take(1)[0] != 0;
        let mut k = [0u8; 30];
        k.copy_from_slice(take(30));
        s.kd.igtk_kde = has_igtk.then_some(k);
        Some(s)
    }

    fn encode_done(d: &Done, o: &mut [u8]) {
        o[0..6].copy_from_slice(&d.sta);
        o[6] = d.akm8 as u8;
        o[7] = d.cached as u8;
        let a = &d.auth;
        let p = &mut o[8..8 + AUTH_LEN];
        p[0..6].copy_from_slice(&a.sta);
        let f = [a.m1_tx, a.m2_rx, a.m2_mic_ok, a.m3_tx, a.m4_rx, a.m4_mic_ok, a.ptk_set, a.gtk_set, a.authorized, a.reassoc, a.deauth]
            .iter().enumerate().fold(0u16, |acc, (k, &v)| acc | ((v as u16) << k));
        p[6..8].copy_from_slice(&f.to_le_bytes());
        p[8..12].copy_from_slice(&a.m1_sends.to_le_bytes());
        p[12..16].copy_from_slice(&a.m3_sends.to_le_bytes());
        p[16..20].copy_from_slice(&a.m2_mic_fail.to_le_bytes());
        p[20..28].copy_from_slice(&a.replay.to_le_bytes());
    }
    fn decode_done(b: &[u8]) -> Done {
        let mut sta = [0u8; 6];
        sta.copy_from_slice(&b[0..6]);
        let p = &b[8..8 + AUTH_LEN];
        let f = u16::from_le_bytes([p[6], p[7]]);
        let bit = |k: u16| f & (1 << k) != 0;
        let mut asta = [0u8; 6];
        asta.copy_from_slice(&p[0..6]);
        let u32_at = |o: usize| u32::from_le_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]]);
        let mut r = [0u8; 8];
        r.copy_from_slice(&p[20..28]);
        Done {
            sta,
            akm8: b[6] != 0,
            cached: b[7] != 0,
            auth: Auth {
                sta: asta, m1_tx: bit(0), m2_rx: bit(1), m2_mic_ok: bit(2), m3_tx: bit(3), m4_rx: bit(4), m4_mic_ok: bit(5),
                ptk_set: bit(6), gtk_set: bit(7), authorized: bit(8), reassoc: bit(9), deauth: bit(10),
                m1_sends: u32_at(8), m3_sends: u32_at(12), m2_mic_fail: u32_at(16), replay: u64::from_le_bytes(r),
            },
        }
    }

    /// `frame` = the keyer's output buffer (for `Out::Send(n)`, its first n bytes are the frame).
    pub fn encode_out(r: &Out, frame: &[u8], o: &mut [u8]) -> usize {
        match r {
            Out::None => {
                o[0] = 0;
                1
            }
            Out::Send(n) => {
                let n = (*n).min(crate::wpakeyer::FRAME_MAX);
                o[0] = 1;
                o[1..3].copy_from_slice(&(n as u16).to_le_bytes());
                o[3..3 + n].copy_from_slice(&frame[..n]);
                3 + n
            }
            Out::Keyed { done, tk } => {
                o[0] = 2;
                encode_done(done, &mut o[1..1 + DONE_LEN]);
                o[1 + DONE_LEN..1 + DONE_LEN + 16].copy_from_slice(tk);
                1 + DONE_LEN + 16
            }
            Out::Failed(d) => {
                o[0] = 3;
                encode_done(d, &mut o[1..1 + DONE_LEN]);
                1 + DONE_LEN
            }
        }
    }
    /// The kernel's side: every length re-checked. `frame` receives a Send's frame.
    pub fn decode_out(b: &[u8], frame: &mut [u8]) -> Option<Out> {
        match *b.first()? {
            0 => Some(Out::None),
            1 => {
                let n = u16::from_le_bytes([*b.get(1)?, *b.get(2)?]) as usize;
                if n > crate::wpakeyer::FRAME_MAX || n > frame.len() {
                    return None;
                }
                frame[..n].copy_from_slice(b.get(3..3 + n)?);
                Some(Out::Send(n))
            }
            2 => {
                let d = decode_done(b.get(1..1 + DONE_LEN)?);
                let mut tk = [0u8; 16];
                tk.copy_from_slice(b.get(1 + DONE_LEN..1 + DONE_LEN + 16)?);
                Some(Out::Keyed { done: d, tk })
            }
            3 => Some(Out::Failed(decode_done(b.get(1..1 + DONE_LEN)?))),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn start_and_out_round_trip() {
            let s = Start { sta: [1; 6], aa: [2; 6], pmk: [3; 32], akm8: true, pmkid: Some([4; 16]), anonce: [5; 32],
                kd: KeyData { rsne: [6; 40], rsne_len: 26, gtk: [7; 16], gtk_keyid: 2, igtk_kde: Some([8; 30]) } };
            let mut b = [0u8; START_LEN];
            assert_eq!(encode_start(&s, &mut b), START_LEN);
            let t = decode_start(&b).unwrap();
            assert!(t.sta == s.sta && t.aa == s.aa && t.pmk == s.pmk && t.akm8 && t.pmkid == s.pmkid && t.anonce == s.anonce);
            assert!(t.kd.rsne_len == 26 && t.kd.rsne == s.kd.rsne && t.kd.gtk == s.kd.gtk && t.kd.gtk_keyid == 2 && t.kd.igtk_kde == s.kd.igtk_kde);
            let mut a = Auth::new();
            a.m2_mic_ok = true;
            a.authorized = true;
            a.m1_sends = 2;
            a.replay = 9;
            let d = Done { sta: [9; 6], akm8: true, cached: false, auth: a };
            let mut o = [0u8; OUT_MAX];
            let mut f = [0u8; 300];
            let n = encode_out(&Out::Keyed { done: d, tk: [0xaa; 16] }, &[], &mut o);
            assert_eq!(decode_out(&o[..n], &mut f), Some(Out::Keyed { done: d, tk: [0xaa; 16] }));
            let n = encode_out(&Out::Send(5), &[1, 2, 3, 4, 5], &mut o);
            assert_eq!(decode_out(&o[..n], &mut f), Some(Out::Send(5)));
            assert_eq!(&f[..5], &[1, 2, 3, 4, 5]);
        }
        #[test]
        fn a_hostile_server_cannot_overflow_the_kernel() {
            let mut f = [0u8; 300];
            assert_eq!(decode_out(&[1, 0xff, 0xff], &mut f), None);
            assert_eq!(decode_out(&[1, 10, 0, 1, 2], &mut f), None, "short");
            assert_eq!(decode_out(&[2, 0], &mut f), None);
            assert_eq!(decode_out(&[9], &mut f), None);
            assert_eq!(decode_out(&[], &mut f), None);
        }
    }
}

// ---- steps 3c / 3d: the WPA3-SAE responder and the PMKSA cache in el0-wifi; the SAE PMK never leaves it ----
/// IN = mode u8 ‖ clear_pmksa u8 ‖ ssid_len u8 ‖ ssid[32] ‖ pw_len u8 ‖ pw[64]. OUT = ok u8.
pub const CMD_SAE_SETUP: u32 = 20;
/// IN = ap 6 ‖ sta 6 ‖ now u64 ‖ rnd[SAE_RND] (fresh TRNG bytes) ‖ the Authentication frame body. OUT = [`saemsg`].
pub const CMD_SAE_RX: u32 = 21;
/// IN = sta 6 ‖ now u64 ‖ offers u8 ‖ the association RSNE facts ([`saemsg::encode_rsn`]). OUT = how ‖ idx ‖
/// diag code ‖ diag age u64 ‖ fresh u8 (the decision only: never a PMK).
pub const CMD_SAE_KEYING: u32 = 22;
/// IN = [`keymsg::encode_start`] (pmk ignored) ‖ now u64 ‖ src u8 (1 = the fresh SAE PMK, 2 = the cached PMKSA) ‖
/// pmkid[16]. The server takes the PMK from its own tables. OUT = [`keymsg::encode_out`].
pub const CMD_KEY_START_SAE: u32 = 23;
/// IN = sta 6 ‖ now u64 ‖ op u8 (0 forget_at, 1 forget, 2 forget_all). OUT = result u8 (forget_at's answer).
pub const CMD_SAE_FORGET: u32 = 24;
/// IN = sta 6 ‖ op u8 (0 remove one, 1 clear all).
pub const CMD_PMKSA_REMOVE: u32 = 25;
/// TRNG bytes the kernel passes per SAE_RX (the server has no TRNG; the exchange draws 32 B at a time, fail-closed).
pub const SAE_RND: usize = 128;

/// The SAE / keying messages (pure; kernel and el0-wifi).
pub mod saemsg {
    use crate::rsnassoc::{AssocRsn, Keying, PMKIDS};

    pub const RSN_LEN: usize = 1 + 4 + 2 + 2 + 16 * PMKIDS;
    pub fn encode_rsn(r: Option<&AssocRsn>, o: &mut [u8]) -> usize {
        o[..RSN_LEN].fill(0);
        if let Some(r) = r {
            o[0] = 1;
            o[1..5].copy_from_slice(&r.akm.to_le_bytes());
            o[5..7].copy_from_slice(&r.n_akm.to_le_bytes());
            o[7..9].copy_from_slice(&r.n_pmkid.to_le_bytes());
            for i in 0..PMKIDS {
                o[9 + 16 * i..25 + 16 * i].copy_from_slice(&r.pmkid[i]);
            }
        }
        RSN_LEN
    }
    pub fn decode_rsn(b: &[u8]) -> Option<Option<AssocRsn>> {
        let b = b.get(..RSN_LEN)?;
        if b[0] == 0 {
            return Some(None);
        }
        let mut r = AssocRsn { akm: u32::from_le_bytes([b[1], b[2], b[3], b[4]]), n_akm: u16::from_le_bytes([b[5], b[6]]),
            n_pmkid: u16::from_le_bytes([b[7], b[8]]), pmkid: [[0; 16]; PMKIDS] };
        for i in 0..PMKIDS {
            r.pmkid[i].copy_from_slice(&b[9 + 16 * i..25 + 16 * i]);
        }
        Some(Some(r))
    }
    pub fn keying_code(k: &Keying) -> (u8, u8) {
        match k {
            Keying::Legacy => (0, 0),
            Keying::Psk => (1, 0),
            Keying::SaeFresh => (2, 0),
            Keying::SaeCached(i) => (3, (*i).min(255) as u8),
            Keying::Reject => (4, 0),
            Keying::SaeNoSae => (5, 0),
            Keying::NotOffered => (6, 0),
            Keying::StaleView => (7, 0),
        }
    }
    pub fn keying_from(c: u8, i: u8) -> Option<Keying> {
        Some(match c {
            0 => Keying::Legacy,
            1 => Keying::Psk,
            2 => Keying::SaeFresh,
            3 => Keying::SaeCached((i as usize).min(PMKIDS - 1)),
            4 => Keying::Reject,
            5 => Keying::SaeNoSae,
            6 => Keying::NotOffered,
            7 => Keying::StaleView,
            _ => return None,
        })
    }

    /// SAE_RX reply: ev u8 (0 none, 1 dropped, 2 committed, 3 accepted, 4 refused) ‖ status u16 ‖ n u8 ‖
    /// 2 × (len u16 ‖ body[FRAME]) ‖ pmkid[16] (Accepted: the PUBLIC PMKID the firmware's auth_status needs).
    pub const FRAME: usize = 104;
    pub const RX_OUT_LEN: usize = 1 + 2 + 1 + 2 * (2 + FRAME) + 16;
    pub struct SaeRx {
        pub ev: u8,
        pub status: u16,
        pub n: usize,
        pub frames: [[u8; FRAME]; 2],
        pub lens: [usize; 2],
        pub pmkid: [u8; 16],
    }
    pub fn decode_rx(b: &[u8]) -> Option<SaeRx> {
        let b = b.get(..RX_OUT_LEN)?;
        let mut r = SaeRx { ev: b[0], status: u16::from_le_bytes([b[1], b[2]]), n: (b[3] as usize).min(2), frames: [[0; FRAME]; 2], lens: [0; 2], pmkid: [0; 16] };
        if r.ev > 4 {
            return None;
        }
        for k in 0..2 {
            let o = 4 + k * (2 + FRAME);
            let l = u16::from_le_bytes([b[o], b[o + 1]]) as usize;
            if l > FRAME {
                return None;
            }
            r.lens[k] = l;
            r.frames[k].copy_from_slice(&b[o + 2..o + 2 + FRAME]);
        }
        r.pmkid.copy_from_slice(&b[RX_OUT_LEN - 16..]);
        Some(r)
    }
    pub fn encode_rx(ev: u8, status: u16, frames: &[&[u8]; 2], n: usize, pmkid: &[u8; 16], o: &mut [u8]) -> usize {
        o[..RX_OUT_LEN].fill(0);
        o[0] = ev;
        o[1..3].copy_from_slice(&status.to_le_bytes());
        o[3] = n.min(2) as u8;
        for (k, f) in frames.iter().enumerate() {
            let l = f.len().min(FRAME);
            let off = 4 + k * (2 + FRAME);
            o[off..off + 2].copy_from_slice(&(l as u16).to_le_bytes());
            o[off + 2..off + 2 + l].copy_from_slice(&f[..l]);
        }
        o[RX_OUT_LEN - 16..RX_OUT_LEN].copy_from_slice(pmkid);
        RX_OUT_LEN
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rsn_keying_and_rx_round_trip() {
            let r = AssocRsn { akm: 0x000fac08, n_akm: 1, n_pmkid: 2, pmkid: [[1; 16], [2; 16], [0; 16], [0; 16]] };
            let mut b = [0u8; RSN_LEN];
            encode_rsn(Some(&r), &mut b);
            let d = decode_rsn(&b).unwrap().unwrap();
            assert!(d.akm == r.akm && d.n_pmkid == 2 && d.pmkid == r.pmkid);
            encode_rsn(None, &mut b);
            assert!(decode_rsn(&b).unwrap().is_none());
            for k in [Keying::Legacy, Keying::Psk, Keying::SaeFresh, Keying::SaeCached(3), Keying::Reject, Keying::SaeNoSae, Keying::NotOffered, Keying::StaleView] {
                let (c, i) = keying_code(&k);
                assert_eq!(keying_from(c, i), Some(k));
            }
            let mut o = [0u8; RX_OUT_LEN];
            encode_rx(3, 0, &[&[7u8; 40], &[8u8; 104]], 2, &[9; 16], &mut o);
            let x = decode_rx(&o).unwrap();
            assert!(x.ev == 3 && x.n == 2 && x.lens == [40, 104] && x.frames[0][..40] == [7; 40] && x.pmkid == [9; 16]);
            o[4] = 0xff;
            o[5] = 0xff;
            assert!(decode_rx(&o).is_none(), "an oversized length from the server is refused");
        }
    }
}

// ---- step 4a: the SDHCI register page granted to el0-wifi (read-only probe first) ----
/// The BCM2712 SDHCI controller the CYW43455 sits on (CM5): the one MMIO page el0-wifi is granted (ADR 0065 D1).
pub const SDHCI_PA_CM5: usize = 0x10_0110_0000;
/// Registers with no read side effect, read by both sides and compared: capabilities 0x40 / 0x44, the host-version
/// word 0xFC (version in [31:16]), present state 0x24, host control 0x28, clock control 0x2C.
pub const PROBE_REGS: [usize; 6] = [0x40, 0x44, 0xFC, 0x24, 0x28, 0x2C];
/// OUT = PROBE_REGS.len() × u32 (LE), read by el0-wifi from its device mapping.
pub const CMD_BUS_PROBE: u32 = 30;

// ---- step 4b-2b: el0-wifi reads one SDPCM frame over its SDHCI grant (`crate::sdio::Bus::read_frame`) ----
/// IN = [`rxmsg::encode_in`]. OUT = [`rxmsg::encode_out`].
pub const CMD_RX_READ: u32 = 31;
/// el0-wifi polls ONCE per `CMD_RX_READ` and never waits: EL0 has no counter access on the CM5 (metal 2026-11-15:
/// a wait inside the server trapped on CNTFRQ/CNTPCT, EC 0x18). A dry budget is the kernel's loop around the calls.
pub const RX_EL0_MAX_DRY: u32 = 0;

/// The frame-read messages. The server's reply is NOT trusted: the kernel re-checks the frame's header itself
/// (`crate::sdpcm_hdr`) and accepts a frame only when the claimed length is the header's.
pub mod rxmsg {
    use crate::sdio::{RxRead, FIRSTREAD};

    pub const IN_LEN: usize = 12;
    /// OUT header: kind, why, chan, flags (1 drained, 2 block), len u16, frame bytes u16, blk_diag u32.
    pub const HDR: usize = 12;
    /// The most frame bytes a reply carries (a successful read is at most 64 + 3 × 512 = 1600 B on this driver).
    pub const FRAME_MAX: usize = super::OUT_MAX - HDR;
    const DRY: u8 = 0;
    const HOST_INT: u8 = 1;
    const BAD_HDR: u8 = 2;
    const SHORT: u8 = 3;
    const FRAME: u8 = 4;

    /// (SDIO core base, dry budget, skip the first intstatus poll, block-mode RX, the kernel's buffer size).
    pub fn encode_in(sdb: u32, max_dry: u32, skip_int: bool, block_rx: bool, cap: usize, o: &mut [u8; IN_LEN]) {
        o[0..4].copy_from_slice(&sdb.to_le_bytes());
        o[4..8].copy_from_slice(&max_dry.to_le_bytes());
        o[8] = skip_int as u8 | (block_rx as u8) << 1;
        o[9] = 0;
        o[10..12].copy_from_slice(&(cap.min(u16::MAX as usize) as u16).to_le_bytes());
    }
    pub fn decode_in(b: &[u8]) -> Option<(u32, u32, bool, bool, usize)> {
        if b.len() != IN_LEN {
            return None;
        }
        let sdb = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let dry = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        Some((sdb, dry, b[8] & 1 != 0, b[8] & 2 != 0, u16::from_le_bytes([b[10], b[11]]) as usize))
    }

    /// The server's reply: the outcome, then (for a frame) its first `max(len, 64)` bytes. Returns the length.
    pub fn encode_out(r: &RxRead, rx: &[u8], blk_diag: u32, o: &mut [u8]) -> usize {
        let (kind, why, chan, flags, len, nb) = match *r {
            RxRead::Dry => (DRY, 0, 0, 0, 0, 0),
            RxRead::HostInt => (HOST_INT, 0, 0, 0, 0, 0),
            RxRead::BadHdr { drained } => (BAD_HDR, 0, 0, drained as u8, 0, 0),
            RxRead::Short { why, hw_len, chan, drained } => (SHORT, why, chan, drained as u8, hw_len, 0),
            RxRead::Frame { hdr, len, block } => {
                let nb = (len as usize).max(FIRSTREAD);
                if nb > FRAME_MAX.min(rx.len()) {
                    // cannot happen on this driver (see FRAME_MAX); report it as a terminated short frame
                    (SHORT, 8, hdr.chan, 0, hdr.len, 0)
                } else {
                    (FRAME, 0, hdr.chan, (block as u8) << 1, len, nb)
                }
            }
        };
        o[0] = kind;
        o[1] = why;
        o[2] = chan;
        o[3] = flags;
        o[4..6].copy_from_slice(&len.to_le_bytes());
        o[6..8].copy_from_slice(&(nb as u16).to_le_bytes());
        o[8..12].copy_from_slice(&blk_diag.to_le_bytes());
        o[HDR..HDR + nb].copy_from_slice(&rx[..nb]);
        HDR + nb
    }

    /// The kernel's side: the outcome and blk_diag; a frame's bytes land in `rx` (the rest of `rx` zeroed: never a
    /// previous frame's bytes, audit M-3 / L-15). None = a malformed or inconsistent reply (the caller counts it and
    /// terminates the frame in the device).
    pub fn decode_out(o: &[u8], rx: &mut [u8]) -> Option<(RxRead, u32)> {
        if o.len() < HDR {
            return None;
        }
        let len = u16::from_le_bytes([o[4], o[5]]);
        let nb = u16::from_le_bytes([o[6], o[7]]) as usize;
        let blk = u32::from_le_bytes([o[8], o[9], o[10], o[11]]);
        let (drained, block) = (o[3] & 1 != 0, o[3] & 2 != 0);
        if o[0] != FRAME && (nb != 0 || o.len() != HDR) {
            return None;
        }
        let r = match o[0] {
            DRY => RxRead::Dry,
            HOST_INT => RxRead::HostInt,
            BAD_HDR => RxRead::BadHdr { drained },
            SHORT if (8..=10).contains(&o[1]) => RxRead::Short { why: o[1], hw_len: len, chan: o[2], drained },
            FRAME => {
                if o.len() != HDR + nb || nb < FIRSTREAD || nb > rx.len() {
                    return None;
                }
                rx[..nb].copy_from_slice(&o[HDR..]);
                for b in rx[nb..].iter_mut() {
                    *b = 0;
                }
                let hdr = match crate::sdpcm_hdr(&rx[..FIRSTREAD]) {
                    Ok(Some(h)) => h,
                    _ => return None,
                };
                if hdr.len != len || nb != (len as usize).max(FIRSTREAD) || hdr.chan != o[2] {
                    return None;
                }
                RxRead::Frame { hdr, len, block }
            }
            _ => return None,
        };
        Some((r, blk))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn frame(len: u16, chan: u8, doff: u8) -> [u8; 2048] {
            let mut b = [0x5au8; 2048];
            b[0..2].copy_from_slice(&len.to_le_bytes());
            b[2..4].copy_from_slice(&(!len).to_le_bytes());
            b[4..8].copy_from_slice(&(7u32 | (chan as u32) << 8 | (doff as u32) << 24).to_le_bytes());
            b[8..12].copy_from_slice(&0x0000_2000u32.to_le_bytes());
            b
        }

        #[test]
        fn input_round_trips() {
            let mut i = [0u8; IN_LEN];
            encode_in(0x1800_2000, 3, true, false, 2048, &mut i);
            assert_eq!(decode_in(&i), Some((0x1800_2000, 3, true, false, 2048)));
            assert_eq!(decode_in(&i[..11]), None);
        }

        #[test]
        fn a_frame_round_trips_and_the_kernel_rechecks_its_header() {
            let src = frame(300, 2, 14);
            let hdr = crate::sdpcm_hdr(&src[..64]).unwrap().unwrap();
            let mut o = [0u8; super::super::OUT_MAX];
            let n = encode_out(&RxRead::Frame { hdr, len: 300, block: false }, &src, 7, &mut o);
            assert_eq!(n, HDR + 300);
            let mut rx = [0xeeu8; 2048];
            assert_eq!(decode_out(&o[..n], &mut rx), Some((RxRead::Frame { hdr, len: 300, block: false }, 7)));
            assert_eq!(rx[..300], src[..300]);
            assert!(rx[300..].iter().all(|&b| b == 0), "the rest of the kernel's buffer is zeroed");
            // a short frame still carries its whole 64-B first read
            let s = frame(40, 1, 12);
            let h2 = crate::sdpcm_hdr(&s[..64]).unwrap().unwrap();
            let n2 = encode_out(&RxRead::Frame { hdr: h2, len: 40, block: false }, &s, 0, &mut o);
            assert_eq!(n2, HDR + 64);
            assert!(matches!(decode_out(&o[..n2], &mut rx), Some((RxRead::Frame { len: 40, .. }, 0))));
        }

        #[test]
        fn a_lying_server_is_refused() {
            let src = frame(300, 2, 14);
            let hdr = crate::sdpcm_hdr(&src[..64]).unwrap().unwrap();
            let mut o = [0u8; super::super::OUT_MAX];
            let n = encode_out(&RxRead::Frame { hdr, len: 300, block: true }, &src, 0, &mut o);
            let mut rx = [0u8; 2048];
            // a claimed length that is not the header's
            let mut bad = o;
            bad[4..6].copy_from_slice(&200u16.to_le_bytes());
            assert_eq!(decode_out(&bad[..n], &mut rx), None);
            // a corrupted header tag
            let mut bad = o;
            bad[HDR] ^= 1;
            assert_eq!(decode_out(&bad[..n], &mut rx), None);
            // more bytes than the kernel's buffer
            assert_eq!(decode_out(&o[..n], &mut rx[..200]), None);
            // a truncated reply
            assert_eq!(decode_out(&o[..n - 1], &mut rx), None);
            // an unknown kind, a bad Short reason, bytes on a non-frame
            let mut z = [0u8; HDR + 1];
            z[0] = 9;
            assert_eq!(decode_out(&z[..HDR], &mut rx), None);
            z[0] = SHORT;
            z[1] = 3;
            assert_eq!(decode_out(&z[..HDR], &mut rx), None);
            z[0] = DRY;
            assert_eq!(decode_out(&z, &mut rx), None);
        }

        #[test]
        fn the_other_outcomes_round_trip() {
            let mut o = [0u8; 64];
            let mut rx = [0u8; 2048];
            for r in [RxRead::Dry, RxRead::HostInt, RxRead::BadHdr { drained: true }, RxRead::Short { why: 9, hw_len: 1700, chan: 2, drained: false }] {
                let n = encode_out(&r, &[], 0x1234, &mut o);
                assert_eq!(decode_out(&o[..n], &mut rx), Some((r, 0x1234)));
            }
        }
    }
}

// ---- step 4c: el0-wifi builds and writes one SDPCM data frame (`crate::sdio::data_frame` / `Bus::write_frame`) ----
/// IN = [`txmsg::encode_in`]. OUT = nothing; R0 = [`txmsg::encode_r0`]. The kernel keeps the credit accounting (the
/// sequence number, the firmware's window and its flow-control mask): it hands the server the sequence to use and
/// advances it only on `Sent`.
pub const CMD_TX_DATA: u32 = 32;

pub mod txmsg {
    use crate::sdio::TxWrite;

    pub const HDR: usize = 4;
    /// The longest ethernet frame a request carries.
    pub const ETH_MAX: usize = 1514;

    /// (sequence, interface, block TX allowed, the ethernet frame) -> the request length.
    pub fn encode_in(seq: u8, ifidx: u8, big_tx: bool, eth: &[u8], o: &mut [u8]) -> Option<usize> {
        if eth.len() > ETH_MAX || o.len() < HDR + eth.len() {
            return None;
        }
        o[0] = seq;
        o[1] = ifidx;
        o[2] = big_tx as u8;
        o[3] = 0;
        o[HDR..HDR + eth.len()].copy_from_slice(eth);
        Some(HDR + eth.len())
    }
    pub fn decode_in(b: &[u8]) -> Option<(u8, u8, bool, &[u8])> {
        if b.len() < HDR || b.len() > HDR + ETH_MAX || b[2] > 1 {
            return None;
        }
        Some((b[0], b[1], b[2] == 1, &b[HDR..]))
    }
    pub fn encode_r0(w: TxWrite) -> u32 {
        match w {
            TxWrite::Sent { block: false } => 1,
            TxWrite::Sent { block: true } => 2,
            TxWrite::TooBig => 3,
            TxWrite::Failed { block: false } => 4,
            TxWrite::Failed { block: true } => 5,
        }
    }
    pub fn decode_r0(r: u32) -> Option<TxWrite> {
        Some(match r {
            1 => TxWrite::Sent { block: false },
            2 => TxWrite::Sent { block: true },
            3 => TxWrite::TooBig,
            4 => TxWrite::Failed { block: false },
            5 => TxWrite::Failed { block: true },
            _ => return None,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips_and_refusals() {
            let mut o = [0u8; super::super::IN_MAX];
            let eth = [0x44u8; 1514];
            let n = encode_in(9, 1, true, &eth, &mut o).unwrap();
            assert_eq!(decode_in(&o[..n]), Some((9, 1, true, &eth[..])));
            assert_eq!(encode_in(0, 0, false, &[0u8; 1515], &mut o), None);
            assert_eq!(decode_in(&o[..3]), None);
            let mut bad = o;
            bad[2] = 7;
            assert_eq!(decode_in(&bad[..n]), None);
            for w in [TxWrite::Sent { block: false }, TxWrite::Sent { block: true }, TxWrite::TooBig, TxWrite::Failed { block: false }, TxWrite::Failed { block: true }] {
                assert_eq!(decode_r0(encode_r0(w)), Some(w));
            }
            assert_eq!(decode_r0(0), None);
            assert_eq!(decode_r0(6), None);
        }
    }
}

// ---- step 4d: el0-wifi builds and writes one control request (`crate::bcdc::request`) ----
/// IN = [`ctlmsg::encode_in`]. OUT = nothing; R0 = 1 written / 4 the write failed (as [`txmsg::encode_r0`]). The
/// kernel keeps the request id, the sequence and the credit, and matches the reply itself (`crate::bcdc::reply`).
pub const CMD_TX_CTL: u32 = 33;

pub mod ctlmsg {
    use crate::bcdc::PAYLOAD_MAX;

    pub const HDR: usize = 20;

    /// (seq, interface, cmd, flags, request id, reply length, payload) -> the request length.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_in(seq: u8, ifidx: u8, cmd: u32, flags: u32, reqid: u16, reply_len: usize, payload: &[u8], o: &mut [u8]) -> Option<usize> {
        if payload.len() > PAYLOAD_MAX || o.len() < HDR + payload.len() || reply_len > u32::MAX as usize {
            return None;
        }
        o[0] = seq;
        o[1] = ifidx;
        o[2..4].fill(0);
        o[4..8].copy_from_slice(&cmd.to_le_bytes());
        o[8..12].copy_from_slice(&flags.to_le_bytes());
        o[12..14].copy_from_slice(&reqid.to_le_bytes());
        o[14..16].fill(0);
        o[16..20].copy_from_slice(&(reply_len as u32).to_le_bytes());
        o[HDR..HDR + payload.len()].copy_from_slice(payload);
        Some(HDR + payload.len())
    }
    /// -> (seq, interface, cmd, flags, request id, reply length, payload).
    #[allow(clippy::type_complexity)]
    pub fn decode_in(b: &[u8]) -> Option<(u8, u8, u32, u32, u16, usize, &[u8])> {
        if b.len() < HDR || b.len() > HDR + PAYLOAD_MAX {
            return None;
        }
        let u = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        Some((b[0], b[1], u(4), u(8), u16::from_le_bytes([b[12], b[13]]), u(16) as usize, &b[HDR..]))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips_and_refusals() {
            let mut o = [0u8; super::super::IN_MAX];
            let n = encode_in(3, 1, 263, 2, 0xbeef, 256, b"ver\0", &mut o).unwrap();
            assert_eq!(decode_in(&o[..n]), Some((3, 1, 263, 2, 0xbeef, 256, &b"ver\0"[..])));
            assert_eq!(encode_in(0, 0, 0, 0, 0, 0, &[0u8; PAYLOAD_MAX + 1], &mut o), None);
            assert_eq!(decode_in(&o[..HDR - 1]), None);
        }
    }
}

#[cfg(test)]
mod bp_reg {
    use super::*;
    #[test]
    fn round_trips_and_refuses_unknown_ops() {
        let b = bp_reg_in(REG_BP_W32, 1, 0x1800_0000, 0xdead_beef);
        assert_eq!(bp_reg_decode(&b), Some((REG_BP_W32, 1, 0x1800_0000, 0xdead_beef)));
        let mut bad = b;
        bad[0] = REG_CMD + 1;
        assert_eq!(bp_reg_decode(&bad), None, "unknown op");
        bad = b;
        bad[1] = 3;
        assert_eq!(bp_reg_decode(&bad), None, "no function 3 on this chip");
        assert_eq!(bp_reg_decode(&b[..11]), None, "short");
        // an SD command: flags (CRC + index check, data phase) ride in the function byte, index | response kind in value
        let c = bp_reg_in(REG_CMD, 3, 0x0012_3400, 5 | (2 << 16));
        assert_eq!(bp_reg_decode(&c), Some((REG_CMD, 3, 0x0012_3400, 5 | (2 << 16))));
        let mut c4 = c;
        c4[1] = 4;
        assert_eq!(bp_reg_decode(&c4), None, "unknown command flag");
        // host registers: width 1/2/4, aligned, inside the SDHCI window
        assert!(bp_reg_decode(&bp_reg_in(REG_HOST_W, 1, 0x29, 0x0f)).is_some());
        assert!(bp_reg_decode(&bp_reg_in(REG_HOST_R, 4, 0x24, 0)).is_some());
        assert_eq!(bp_reg_decode(&bp_reg_in(REG_HOST_R, 3, 0x24, 0)), None, "width 3");
        assert_eq!(bp_reg_decode(&bp_reg_in(REG_HOST_R, 4, 0x26, 0)), None, "unaligned");
        assert_eq!(bp_reg_decode(&bp_reg_in(REG_HOST_W, 4, 0x1000, 0)), None, "outside the window");
    }
}

#[cfg(test)]
mod cmd_numbers {
    /// el0-wifi dispatches one `match` over its own commands AND `wpasrvabi::CMD_KEY_INSTALL`: a shared number sends
    /// one command to the other's handler (step 4e-1's first CMD_BP_WRITE took 35 = CMD_KEY_INSTALL; QEMU S3c caught it).
    #[test]
    fn every_command_el0_wifi_dispatches_has_its_own_number() {
        use super::*;
        let all = [
            CMD_INIT, CMD_POLL, CMD_BUS_PROBE, CMD_RX_READ, CMD_TX_DATA, CMD_TX_CTL, CMD_KEYX_PEEK, CMD_BP_WRITE, CMD_BP_REG,
            crate::wpasrvabi::CMD_KEY_INSTALL, CMD_INJECT_READ_VA, CMD_INJECT_CMD53_STALL, CMD_SELFTEST_KEYX_WRITE,
            CMD_SELFTEST_BAD_RING, CMD_SELFTEST_FAULT,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "two el0-wifi commands share the number {a}");
            }
        }
    }
}
