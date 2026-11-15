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
pub const STACK_SIZE: usize = 0x8000;
/// One page: the command block below.
pub const CTRL_OFF: usize = 0x2_8000;
/// One page: the device the kernel granted (step 2: the fake device; step 4: the SDHCI registers).
pub const DEV_OFF: usize = 0x2_9000;
/// Driver -> kernel frames (received from the device).
pub const RX_OFF: usize = 0x3_0000;
/// Kernel -> driver frames (to send to the device).
pub const TX_OFF: usize = RX_OFF + crate::el0ring::RING_BYTES + 0x1000;
/// The window's end, relative to the base (must stay inside the platform's user window).
pub const WINDOW_END: usize = TX_OFF + crate::el0ring::RING_BYTES;

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
/// Test only: fault on purpose (the supervisor's restart path).
pub const CMD_SELFTEST_FAULT: u32 = 99;

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
