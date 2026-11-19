// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0065 step 3a: the WPA 4-way authenticator as a PURE state machine.
//!
//! It is the non-blocking keyer of #1200, lifted out of the CYW43455 driver with no I/O and no statics:
//! - the caller sends the frames it returns (`Out::Send`);
//! - on `Out::Keyed` the caller installs the pairwise key and authorizes the station;
//! - the MIC / PTK / MFP work goes through [`KeyCrypto`]. The kernel's implementation calls the EL0 LAN-services
//!   server (ADR 0050 D4 step 5b); `el0-wifi` (step 3b) calls `hal::wpaauth` directly.
//!
//! Frames, replay counters and timing are the same as the in-driver keyer: M1 at start, M3 after a verified M2,
//! resend after `RESEND_MS` with replay+1, give up after `MAX_SENDS`.
//!
//! Key material (PMK, KCK, TK, GTK, IGTK, the wrapped key data) is wiped when a slot clears; it never appears in
//! `Out` except the TK in `Out::Keyed`, which the caller installs and wipes. Host-tested and fuzzed (`wpa_keyer`).

use crate::wpaauth::wipe;

pub const RESEND_MS: u64 = 1000;
pub const MAX_SENDS: u32 = 3;
pub const SLOTS: usize = 4;
/// The largest frame the keyer produces (M3 with 144 B of wrapped key data).
pub const FRAME_MAX: usize = 14 + 4 + 95 + 144;
const BODY: usize = 18;

/// Per-handshake counters (the driver's `ApAuth`; the loop prints them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Auth {
    pub sta: [u8; 6],
    pub m1_tx: bool,
    pub m2_rx: bool,
    pub m2_mic_ok: bool,
    pub m3_tx: bool,
    pub m4_rx: bool,
    pub m4_mic_ok: bool,
    pub ptk_set: bool,
    pub gtk_set: bool,
    pub authorized: bool,
    pub reassoc: bool,
    pub deauth: bool,
    pub m1_sends: u32,
    pub m3_sends: u32,
    pub m2_mic_fail: u32,
    pub replay: u64,
}
impl Auth {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The crypto the keyer needs; implemented by the kernel (via EL0) and by el0-wifi (directly).
pub trait KeyCrypto {
    /// M2: the PTK (KCK ‖ KEK ‖ TK) if its MIC verifies under the PTK derived from the station's SNonce.
    fn m2(&mut self, pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], akm8: bool, m2: &[u8]) -> Option<[u8; 48]>;
    /// M4: does its MIC verify?
    fn m4(&mut self, kck: &[u8; 16], akm8: bool, m4: &[u8]) -> bool;
    /// Does the station's M2 RSNE advertise MFP-capable?
    fn m2_mfpc(&mut self, m2: &[u8], body_off: usize) -> bool;
}

/// `hal::wpaauth` directly (el0-wifi; tests).
pub struct Direct;
impl KeyCrypto for Direct {
    fn m2(&mut self, pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], akm8: bool, m2: &[u8]) -> Option<[u8; 48]> {
        crate::wpaauth::on_m2(pmk, aa, spa, anonce, akm8, m2)
    }
    fn m4(&mut self, kck: &[u8; 16], akm8: bool, m4: &[u8]) -> bool {
        crate::wpaauth::on_m4(kck, akm8, m4)
    }
    fn m2_mfpc(&mut self, m2: &[u8], body_off: usize) -> bool {
        crate::eapolwire::m2_mfpc(m2, body_off)
    }
}

/// What M3 carries, prepared by the caller at start.
#[derive(Clone, Copy)]
pub struct KeyData {
    /// The RSNE (‖ RSNXE) the BSS beacons.
    pub rsne: [u8; 40],
    pub rsne_len: usize,
    pub gtk: [u8; 16],
    pub gtk_keyid: u8,
    /// The IGTK KDE, added when the station negotiates PMF (None = this BSS does not offer PMF).
    pub igtk_kde: Option<[u8; 30]>,
}

/// One handshake to start.
#[derive(Clone, Copy)]
pub struct Start {
    pub sta: [u8; 6],
    pub aa: [u8; 6],
    pub pmk: [u8; 32],
    pub akm8: bool,
    pub pmkid: Option<[u8; 16]>,
    /// From the hardware TRNG (the caller's; fail-closed there).
    pub anonce: [u8; 32],
    pub kd: KeyData,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    M2,
    M4,
}

#[derive(Clone, Copy)]
struct Slot {
    s: Start,
    replay: u64,
    stage: Stage,
    last_ms: u64,
    kck: [u8; 16],
    tk: [u8; 16],
    wrapped: [u8; 144],
    kdw: usize,
    auth: Auth,
}

/// A finished or abandoned handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    pub sta: [u8; 6],
    pub akm8: bool,
    /// The handshake used a cached PMKSA (PMKID in M1).
    pub cached: bool,
    pub auth: Auth,
}

/// What the caller must do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    None,
    /// Send `out[..len]` to the station.
    Send(usize),
    /// M4 verified: install `tk` as the station's pairwise key, authorize it, then report the handshake (with
    /// `ptk_set` / `authorized` filled in). The caller wipes `tk`.
    Keyed { done: Done, tk: [u8; 16] },
    /// Over without keys (no answer after MAX_SENDS, or the key data could not be wrapped).
    Failed(Done),
}

pub struct Keyer {
    slots: [Option<Slot>; SLOTS],
}

impl Default for Keyer {
    fn default() -> Self {
        Self::new()
    }
}

fn clear(o: &mut Option<Slot>) {
    if let Some(s) = o.as_mut() {
        wipe(&mut s.s.pmk);
        wipe(&mut s.s.kd.gtk);
        if let Some(k) = s.s.kd.igtk_kde.as_mut() {
            wipe(k);
        }
        wipe(&mut s.kck);
        wipe(&mut s.tk);
        wipe(&mut s.wrapped);
    }
    *o = None;
}

/// M1: pairwise | ACK, descriptor 0x008a (v2) / 0x0088 (v0, AKM 8); the PMKID KDE when keying a cached PMKSA.
pub fn build_m1(m1: &mut [u8], sta: &[u8; 6], aa: &[u8; 6], anonce: &[u8; 32], replay: u64, akm8: bool, pmkid: Option<&[u8; 16]>) -> usize {
    let ki: u16 = if akm8 { 0x0088 } else { 0x008a };
    m1[..BODY + 95 + 22].fill(0);
    let kd = if let Some(p) = pmkid {
        m1[BODY + 95..BODY + 101].copy_from_slice(&[0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04]);
        m1[BODY + 101..BODY + 117].copy_from_slice(p);
        22
    } else {
        0
    };
    m1[BODY + 93..BODY + 95].copy_from_slice(&(kd as u16).to_be_bytes());
    m1[0..6].copy_from_slice(sta);
    m1[6..12].copy_from_slice(aa);
    m1[12] = 0x88;
    m1[13] = 0x8E;
    m1[14] = 2; // 802.1X version 2
    m1[15] = 0x03; // EAPOL-Key
    m1[16..18].copy_from_slice(&((95 + kd) as u16).to_be_bytes());
    m1[BODY] = 0x02; // RSN key descriptor
    m1[BODY + 1..BODY + 3].copy_from_slice(&ki.to_be_bytes());
    m1[BODY + 3..BODY + 5].copy_from_slice(&16u16.to_be_bytes()); // CCMP pairwise key length
    m1[BODY + 5..BODY + 13].copy_from_slice(&replay.to_be_bytes());
    m1[BODY + 13..BODY + 45].copy_from_slice(anonce);
    BODY + 95 + kd
}

/// M3: pairwise|install|ack|mic|secure|encrypted, 0x13ca (v2) / 0x13c8 (v0), re-MIC'd per send (the MIC covers
/// the replay counter).
pub fn build_m3(m3: &mut [u8], sta: &[u8; 6], aa: &[u8; 6], anonce: &[u8; 32], replay: u64, kck: &[u8; 16], wrapped: &[u8], akm8: bool) -> usize {
    let ki: u16 = if akm8 { 0x13c8 } else { 0x13ca };
    let kdw = wrapped.len().min(144);
    m3[..FRAME_MAX].fill(0);
    m3[0..6].copy_from_slice(sta);
    m3[6..12].copy_from_slice(aa);
    m3[12] = 0x88;
    m3[13] = 0x8E;
    m3[14] = 2;
    m3[15] = 0x03;
    m3[16..18].copy_from_slice(&((95 + kdw) as u16).to_be_bytes());
    m3[BODY] = 0x02;
    m3[BODY + 1..BODY + 3].copy_from_slice(&ki.to_be_bytes());
    m3[BODY + 3..BODY + 5].copy_from_slice(&16u16.to_be_bytes());
    m3[BODY + 5..BODY + 13].copy_from_slice(&replay.to_be_bytes());
    m3[BODY + 13..BODY + 45].copy_from_slice(anonce);
    m3[BODY + 93..BODY + 95].copy_from_slice(&(kdw as u16).to_be_bytes());
    m3[BODY + 95..BODY + 95 + kdw].copy_from_slice(&wrapped[..kdw]);
    let end = BODY + 95 + kdw;
    let mic = crate::wpaauth::mic(kck, &m3[14..end], akm8); // MIC field still zero
    m3[BODY + 77..BODY + 93].copy_from_slice(&mic);
    end
}

impl Keyer {
    pub const fn new() -> Self {
        Keyer { slots: [None; SLOTS] }
    }

    /// Handshakes in progress.
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Is `sta` keying, and what does its next EAPOL-Key frame need: (Secure bit, replay counter)?
    pub fn expect(&self, sta: &[u8; 6]) -> Option<(bool, u64)> {
        self.slots.iter().flatten().find(|s| s.s.sta == *sta).map(|s| (s.stage == Stage::M4, s.replay))
    }

    /// Start (or restart, on a re-association) the handshake: M1 into `out`. A full table evicts the oldest.
    pub fn start(&mut self, st: Start, now_ms: u64, out: &mut [u8]) -> Out {
        let i = self.slots.iter().position(|s| s.is_some_and(|s| s.s.sta == st.sta))
            .or_else(|| self.slots.iter().position(|s| s.is_none()))
            .unwrap_or_else(|| (0..SLOTS).min_by_key(|&i| self.slots[i].map_or(0, |s| s.last_ms)).unwrap_or(0));
        clear(&mut self.slots[i]);
        let mut auth = Auth::new();
        auth.sta = st.sta;
        auth.m1_tx = true;
        auth.m1_sends = 1;
        auth.replay = 1;
        let n = build_m1(out, &st.sta, &st.aa, &st.anonce, 1, st.akm8, st.pmkid.as_ref());
        self.slots[i] = Some(Slot { s: st, replay: 1, stage: Stage::M2, last_ms: now_ms, kck: [0; 16], tk: [0; 16], wrapped: [0; 144], kdw: 0, auth });
        Out::Send(n)
    }

    /// The station left: forget its handshake.
    pub fn abort(&mut self, sta: &[u8; 6]) {
        for o in self.slots.iter_mut() {
            if o.is_some_and(|s| s.s.sta == *sta) {
                clear(o);
            }
        }
    }

    /// A classified EAPOL-Key frame from `sta` (the 802.1X frame, as `expect` asked for).
    pub fn on_eapol<C: KeyCrypto>(&mut self, sta: &[u8; 6], m: &[u8], now_ms: u64, c: &mut C, out: &mut [u8]) -> Out {
        let Some(i) = self.slots.iter().position(|s| s.is_some_and(|s| s.s.sta == *sta)) else { return Out::None };
        let s = self.slots[i].as_mut().unwrap();
        let r = match s.stage {
            Stage::M2 => {
                s.auth.m2_rx = true;
                on_m2(s, m, now_ms, c, out)
            }
            Stage::M4 => {
                s.auth.m4_rx = true;
                on_m4(s, m, c)
            }
        };
        match r {
            Out::Keyed { .. } | Out::Failed(_) => clear(&mut self.slots[i]),
            _ => {}
        }
        r
    }

    /// Once per loop iteration: one due resend, or one handshake given up.
    pub fn tick(&mut self, now_ms: u64, out: &mut [u8]) -> Out {
        for i in 0..SLOTS {
            let Some(s) = self.slots[i].as_mut() else { continue };
            if now_ms.wrapping_sub(s.last_ms) < RESEND_MS {
                continue;
            }
            let sends = if s.stage == Stage::M2 { s.auth.m1_sends } else { s.auth.m3_sends };
            if sends >= MAX_SENDS {
                let d = Done { sta: s.s.sta, akm8: s.s.akm8, cached: s.s.pmkid.is_some(), auth: s.auth };
                clear(&mut self.slots[i]);
                return Out::Failed(d);
            }
            s.replay += 1;
            s.auth.replay = s.replay;
            s.last_ms = now_ms;
            let n = if s.stage == Stage::M2 {
                s.auth.m1_sends += 1;
                build_m1(out, &s.s.sta, &s.s.aa, &s.s.anonce, s.replay, s.s.akm8, s.s.pmkid.as_ref())
            } else {
                s.auth.m3_sends += 1;
                build_m3(out, &s.s.sta, &s.s.aa, &s.s.anonce, s.replay, &s.kck, &s.wrapped[..s.kdw], s.s.akm8)
            };
            return Out::Send(n);
        }
        Out::None
    }
}

fn done(s: &Slot) -> Done {
    Done { sta: s.s.sta, akm8: s.s.akm8, cached: s.s.pmkid.is_some(), auth: s.auth }
}

fn on_m2<C: KeyCrypto>(s: &mut Slot, m2: &[u8], now_ms: u64, c: &mut C, out: &mut [u8]) -> Out {
    let Some(mut ptk) = c.m2(&s.s.pmk, &s.s.aa, &s.s.sta, &s.s.anonce, s.s.akm8, m2) else {
        s.auth.m2_mic_fail += 1; // wrong PSK, forged, or stale — keep waiting (hostapd)
        return Out::None;
    };
    s.auth.m2_mic_ok = true;
    s.kck.copy_from_slice(&ptk[0..16]);
    let mut kek = [0u8; 16];
    kek.copy_from_slice(&ptk[16..32]);
    s.tk.copy_from_slice(&ptk[32..48]);
    wipe(&mut ptk);
    // PMF: offered by this BSS (an IGTK KDE was prepared) and the station's M2 RSNE says MFP-capable
    let pmf = s.s.kd.igtk_kde.is_some() && c.m2_mfpc(m2, BODY - 14);
    // M3 key data = RSNE ++ GTK-KDE [++ IGTK-KDE], padded to /8, AES-key-wrapped under KEK
    let mut kd = [0u8; 136];
    let rl = s.s.kd.rsne_len.min(40);
    kd[..rl].copy_from_slice(&s.s.kd.rsne[..rl]);
    let kln = crate::wpa::wpa_gtk_kde(s.s.kd.gtk_keyid, &s.s.kd.gtk, &mut kd[rl..]);
    let mut plen = rl + kln;
    if pmf {
        if let Some(k) = s.s.kd.igtk_kde.as_ref() {
            kd[plen..plen + 30].copy_from_slice(k);
            plen += 30;
        }
    }
    let unpadded = plen;
    while plen % 8 != 0 {
        kd[plen] = if plen == unpadded { 0xdd } else { 0x00 };
        plen += 1;
    }
    let w = crate::aes::aes_wrap(&kek, &kd[..plen], &mut s.wrapped);
    wipe(&mut kek);
    wipe(&mut kd);
    let Some(kdw) = w else { return Out::Failed(done(s)) };
    s.kdw = kdw;
    s.replay += 1;
    s.stage = Stage::M4;
    s.auth.m3_tx = true;
    s.auth.m3_sends = 1;
    s.auth.replay = s.replay;
    s.last_ms = now_ms;
    Out::Send(build_m3(out, &s.s.sta, &s.s.aa, &s.s.anonce, s.replay, &s.kck, &s.wrapped[..s.kdw], s.s.akm8))
}

fn on_m4<C: KeyCrypto>(s: &mut Slot, m4: &[u8], c: &mut C) -> Out {
    let mic_off = (BODY - 14) + 77;
    if !(mic_off + 16 <= m4.len() && c.m4(&s.kck, s.s.akm8, m4)) {
        s.auth.m2_mic_fail += 1;
        return Out::None;
    }
    s.auth.m4_mic_ok = true;
    Out::Keyed { done: done(s), tk: s.tk }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AA: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
    const SPA: [u8; 6] = [0x02, 0x5a, 0, 0, 0, 9];

    fn start(akm8: bool, pmf: bool) -> Start {
        let mut rsne = [0u8; 40];
        rsne[..4].copy_from_slice(&[0x30, 0x02, 0x01, 0x00]);
        Start {
            sta: SPA,
            aa: AA,
            pmk: [0x11; 32],
            akm8,
            pmkid: None,
            anonce: [0x22; 32],
            kd: KeyData { rsne, rsne_len: 4, gtk: [0x33; 16], gtk_keyid: 1, igtk_kde: if pmf { Some([0x44; 30]) } else { None } },
        }
    }

    /// A station's M2 / M4 built the way a supplicant would (the PTK from our ANonce and its SNonce).
    fn station_frame(akm8: bool, kck: &[u8; 16], replay: u64, secure: bool, snonce: &[u8; 32]) -> ([u8; 128], usize) {
        let mut f = [0u8; 128];
        let n = 4 + 95;
        f[0] = 2;
        f[1] = 3;
        f[2..4].copy_from_slice(&95u16.to_be_bytes());
        f[4] = 2;
        let ki: u16 = (if secure { 0x0300 } else { 0x0100 }) | if akm8 { 0x0008 } else { 0x000a };
        f[5..7].copy_from_slice(&ki.to_be_bytes());
        f[9..17].copy_from_slice(&replay.to_be_bytes());
        if !secure {
            f[17..49].copy_from_slice(snonce);
        }
        let mic = crate::wpaauth::mic(kck, &f[..n], akm8);
        f[81..97].copy_from_slice(&mic);
        (f, n)
    }

    #[test]
    fn a_full_handshake_keys_the_station() {
        for akm8 in [false, true] {
            let mut k = Keyer::new();
            let mut out = [0u8; FRAME_MAX];
            let st = start(akm8, false);
            assert!(matches!(k.start(st, 0, &mut out), Out::Send(_)));
            assert_eq!(k.expect(&SPA), Some((false, 1)));
            let snonce = [0x55u8; 32];
            let ptk = crate::wpaauth::ptk(akm8, &st.pmk, &AA, &SPA, &st.anonce, &snonce);
            let mut kck = [0u8; 16];
            kck.copy_from_slice(&ptk[..16]);
            let (m2, n) = station_frame(akm8, &kck, 1, false, &snonce);
            let r = k.on_eapol(&SPA, &m2[..n], 10, &mut Direct, &mut out);
            assert!(matches!(r, Out::Send(_)), "M3 sent");
            assert_eq!(k.expect(&SPA), Some((true, 2)));
            let (m4, n) = station_frame(akm8, &kck, 2, true, &snonce);
            match k.on_eapol(&SPA, &m4[..n], 20, &mut Direct, &mut out) {
                Out::Keyed { done, tk } => {
                    assert_eq!(tk[..], ptk[32..48]);
                    assert!(done.auth.m2_mic_ok && done.auth.m4_mic_ok && done.auth.m3_sends == 1);
                }
                o => panic!("{o:?}"),
            }
            assert_eq!(k.pending(), 0);
        }
    }

    #[test]
    fn a_wrong_psk_never_keys_and_gives_up_after_three_sends() {
        let mut k = Keyer::new();
        let mut out = [0u8; FRAME_MAX];
        k.start(start(false, false), 0, &mut out);
        let (m2, n) = station_frame(false, &[0u8; 16], 1, false, &[1; 32]);
        assert_eq!(k.on_eapol(&SPA, &m2[..n], 10, &mut Direct, &mut out), Out::None);
        assert_eq!(k.tick(500, &mut out), Out::None, "not due");
        assert!(matches!(k.tick(1000, &mut out), Out::Send(_)), "M1 again");
        assert_eq!(k.expect(&SPA), Some((false, 2)), "replay+1 per resend");
        assert!(matches!(k.tick(2000, &mut out), Out::Send(_)));
        match k.tick(3000, &mut out) {
            Out::Failed(d) => assert!(d.auth.m1_sends == 3 && d.auth.m2_mic_fail == 1 && !d.auth.m2_mic_ok),
            o => panic!("{o:?}"),
        }
        assert_eq!(k.pending(), 0);
    }

    #[test]
    fn abort_reassoc_and_eviction() {
        let mut k = Keyer::new();
        let mut out = [0u8; FRAME_MAX];
        k.start(start(false, false), 0, &mut out);
        k.abort(&SPA);
        assert_eq!(k.expect(&SPA), None);
        // a re-association restarts in the same slot
        k.start(start(false, false), 0, &mut out);
        k.start(start(false, false), 5, &mut out);
        assert_eq!(k.pending(), 1);
        // a full table evicts the oldest
        for i in 0..SLOTS as u8 + 1 {
            let mut s = start(false, false);
            s.sta[5] = 100 + i;
            k.start(s, 10 + i as u64, &mut out);
        }
        assert_eq!(k.pending(), SLOTS);
        assert_eq!(k.expect(&SPA), None, "the oldest went first");
    }

    #[test]
    fn m1_carries_the_pmkid_when_keying_a_cached_pmksa() {
        let mut out = [0u8; FRAME_MAX];
        let n = build_m1(&mut out, &SPA, &AA, &[0; 32], 1, true, Some(&[0x77; 16]));
        assert_eq!(n, 18 + 95 + 22);
        assert_eq!(&out[18 + 95..18 + 101], &[0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04]);
        assert_eq!(&out[18 + 1..18 + 3], &0x0088u16.to_be_bytes());
    }
}
