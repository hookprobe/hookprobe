//! The station's RSNE from its (Re)Association Request — attacker-shaped bytes from anyone in radio range — and the
//! AP's keying decision (IEEE 802.11-2020 12.6.10.3 / 12.7, what hostapd's `wpa_validate_wpa_ie` decides).
//!
//! The CYW43455 FullMAC firmware answers the association itself and then raises WLC_E_ASSOC_IND / REASSOC_IND whose
//! event data is the request's information elements (brcmfmac hands exactly that buffer to cfg80211 as
//! `assoc_req_ies`). The AP's host authenticator must key the 4-way with the AKM the STATION chose there:
//! - AKM 8 (SAE) right after a full SAE exchange -> that SAE PMK;
//! - AKM 8 with a PMKID we hold for this station (PMKSA caching, open-system auth, no SAE) -> the cached PMK;
//! - AKM 8 with no PMKID we know -> refuse (the station must redo SAE; keying it as PSK can never succeed);
//! - AKM 2 (PSK) -> the passphrase PMK;
//! - an AKM the BSS does not offer right now (AKM 8 on a WPA2-only BSS, AKM 2 on a WPA3-only one — a station with a
//!   stale scan after a live security change, metal 2026-11-12) -> refuse with reason 20 (invalid AKMP).
//! Anything this parser cannot read keeps the earlier behaviour (`Legacy`). Pure, allocation-free, no secrets.

/// 00-0F-AC:2 PSK and 00-0F-AC:8 SAE, as (OUI << 8 | type).
pub const AKM_PSK: u32 = 0x000f_ac02;
pub const AKM_SAE: u32 = 0x000f_ac08;
/// PMKIDs kept from one RSNE (a station lists one; more are ignored, the count is kept).
pub const PMKIDS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssocRsn {
    /// The station's (single) AKM suite; 00-0F-AC:1 when the RSNE ends before the AKM list (the spec default).
    pub akm: u32,
    /// AKM suites listed (a (re)association request names exactly one).
    pub n_akm: u16,
    /// PMKIDs listed (may exceed the ones kept).
    pub n_pmkid: u16,
    pub pmkid: [[u8; 16]; PMKIDS],
}

impl AssocRsn {
    /// The PMKIDs kept, in station order.
    pub fn pmkids(&self) -> &[[u8; 16]] {
        &self.pmkid[..(self.n_pmkid as usize).min(PMKIDS)]
    }
}

fn u16le(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// One RSNE body (after element id + length). None = malformed (wrong version, a list running past the end).
pub fn rsne_body(b: &[u8]) -> Option<AssocRsn> {
    let mut r = AssocRsn { akm: 0x000f_ac01, n_akm: 0, n_pmkid: 0, pmkid: [[0; 16]; PMKIDS] };
    if u16le(b, 0)? != 1 {
        return None;
    }
    // every field after the version is optional, but a started field must be complete (12.6.3 / 9.4.2.24)
    let mut i = 2 + 4; // version, group data cipher
    if b.len() < i {
        return if b.len() == 2 { Some(r) } else { None };
    }
    for list in 0..2 {
        if b.len() == i {
            return Some(r);
        }
        let n = u16le(b, i)? as usize;
        i += 2;
        if b.len() < i + n * 4 {
            return None;
        }
        if list == 1 {
            r.n_akm = n as u16;
            if n > 0 {
                r.akm = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
            }
        }
        i += n * 4;
    }
    if b.len() == i {
        return Some(r);
    }
    i += 2; // RSN capabilities
    if b.len() < i {
        return None;
    }
    if b.len() == i {
        return Some(r);
    }
    let n = u16le(b, i)? as usize;
    i += 2;
    if b.len() < i + n * 16 {
        return None;
    }
    r.n_pmkid = n as u16;
    for k in 0..n.min(PMKIDS) {
        r.pmkid[k].copy_from_slice(&b[i + k * 16..i + k * 16 + 16]);
    }
    Some(r) // group management cipher etc. follow — not needed here
}

/// The RSNE body in an element list (walk stops at the first element running past the end).
pub fn find_rsne(ies: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let l = ies[i + 1] as usize;
        if i + 2 + l > ies.len() {
            return None;
        }
        if ies[i] == 0x30 {
            return Some(&ies[i + 2..i + 2 + l]);
        }
        i += 2 + l;
    }
    None
}

/// The station's RSN choice from the ASSOC_IND / REASSOC_IND event data. The data is the request's element list
/// (brcmfmac); offsets 4 / 10 (the fixed fields of an Association / Reassociation Request body) are tried only when
/// no RSNE is found at 0, so a firmware that hands over the whole body still parses. None = no readable RSNE.
pub fn assoc_rsn(data: &[u8]) -> Option<AssocRsn> {
    for off in [0usize, 4, 10] {
        if let Some(b) = data.get(off..).and_then(find_rsne) {
            return rsne_body(b);
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Keying {
    /// No readable RSNE / another AKM: the earlier rule (a just-completed SAE keys as SAE, otherwise PSK).
    Legacy,
    /// AKM 2: the passphrase PMK.
    Psk,
    /// AKM 8 right after a full SAE exchange: that PMK.
    SaeFresh,
    /// AKM 8 + the station's PMKID at this index matches a cached PMKSA for it.
    SaeCached(usize),
    /// AKM 8 + PMKIDs, none of which we hold: refuse (deauthenticate, reason 49 invalid PMKID) so it redoes SAE.
    Reject,
    /// AKM 8 with no PMKID and no fresh SAE: refuse (reason 49).
    SaeNoSae,
    /// An AKM the BSS does not offer now (`offers`): refuse (reason 20 invalid AKMP).
    NotOffered,
}

impl Keying {
    pub fn name(&self) -> &'static str {
        match self {
            Keying::Legacy => "no readable RSNE: previous rule",
            Keying::Psk => "PSK",
            Keying::SaeFresh => "SAE (just authenticated)",
            Keying::SaeCached(_) => "SAE (cached PMKSA)",
            Keying::Reject => "SAE with an unknown PMKID: reject",
            Keying::SaeNoSae => "SAE AKM without SAE: reject",
            Keying::NotOffered => "AKM not offered by this BSS: reject",
        }
    }
    /// The deauthentication reason for a refusal; None = key the 4-way.
    pub fn reason(&self) -> Option<u16> {
        match self {
            Keying::Reject | Keying::SaeNoSae => Some(REASON_INVALID_PMKID),
            Keying::NotOffered => Some(REASON_INVALID_AKMP),
            _ => None,
        }
    }
}

/// Reason code 49: invalid PMKID (IEEE 802.11-2020 Table 9-49).
pub const REASON_INVALID_PMKID: u16 = 49;
/// Reason code 20: invalid AKMP.
pub const REASON_INVALID_AKMP: u16 = 20;
/// The AKMs the BSS offers (`decide`'s `offers`): WPA2-PSK = PSK, WPA3-SAE = SAE, transition = both.
pub const OFFER_PSK: u8 = 1;
pub const OFFER_SAE: u8 = 2;

/// The keying decision. `fresh_sae` = this station completed SAE within the responder TTL; `known` = a PMKID that a
/// cached PMKSA of this station carries; `offers` = OFFER_* bits of the BSS's current security.
pub fn decide(rsn: Option<&AssocRsn>, offers: u8, fresh_sae: bool, known: &mut dyn FnMut(&[u8; 16]) -> bool) -> Keying {
    let Some(r) = rsn else { return Keying::Legacy };
    if r.n_akm != 1 {
        return Keying::Legacy;
    }
    match r.akm {
        AKM_PSK if offers & OFFER_PSK == 0 => Keying::NotOffered,
        AKM_SAE if offers & OFFER_SAE == 0 => Keying::NotOffered,
        AKM_PSK => Keying::Psk,
        AKM_SAE if fresh_sae => Keying::SaeFresh,
        AKM_SAE if r.n_pmkid == 0 => Keying::SaeNoSae,
        AKM_SAE => r.pmkids().iter().position(|p| known(p)).map_or(Keying::Reject, Keying::SaeCached),
        _ => Keying::Legacy,
    }
}

fn mac64(m: &[u8; 6]) -> u64 {
    u64::from_le_bytes([m[0], m[1], m[2], m[3], m[4], m[5], 0, 0])
}

/// Per-station log rate limit. The refusal path (burst 1): a station with a stale scan re-associates every ~15 s for
/// as long as it likes (134 times in 35 min on metal) — its first refusal is logged, then one line per `WINDOW_MS`
/// with the count; the deauthentication failure detail once per station. The SAE trace (burst > 1): the first
/// `burst` lines of a station per window, then the count on its next line. Bounded (the oldest window is reused).
pub struct RejectLog {
    e: [RejEntry; 8],
    burst: u8,
}
#[derive(Clone, Copy)]
struct RejEntry {
    /// the station MAC as a u64
    sta: u64,
    used: bool,
    /// events since the last logged line
    n: u32,
    /// lines logged in the current window, which started at `win_ms`
    lines: u8,
    win_ms: u64,
    fail_logged: bool,
}
impl RejectLog {
    pub const WINDOW_MS: u64 = 30_000;
    pub const fn new() -> RejectLog {
        RejectLog::with_burst(1)
    }
    pub const fn with_burst(burst: u8) -> RejectLog {
        RejectLog { e: [RejEntry { sta: 0, used: false, n: 0, lines: 0, win_ms: 0, fail_logged: false }; 8], burst }
    }
    #[inline(never)]
    fn slot(&self, sta: &[u8; 6]) -> Option<usize> {
        let k = mac64(sta);
        (0..self.e.len()).find(|&i| self.e[i].used && self.e[i].sta == k)
    }
    /// One event of `sta`. Some(n) = log a line now (n events including this one since its last line).
    pub fn note(&mut self, sta: &[u8; 6], now_ms: u64) -> Option<u32> {
        let i = match self.slot(sta) {
            Some(i) => i,
            None => {
                // a free slot, else the oldest window
                let mut i = 0;
                for k in 1..self.e.len() {
                    if (self.e[k].used, self.e[k].win_ms) < (self.e[i].used, self.e[i].win_ms) {
                        i = k;
                    }
                }
                self.e[i] = RejEntry { sta: mac64(sta), used: true, n: 0, lines: 0, win_ms: now_ms, fail_logged: false };
                i
            }
        };
        let x = &mut self.e[i];
        x.n = x.n.saturating_add(1);
        if now_ms.wrapping_sub(x.win_ms) >= Self::WINDOW_MS {
            x.win_ms = now_ms;
            x.lines = 0;
        }
        if x.lines >= self.burst {
            return None;
        }
        x.lines += 1;
        Some(core::mem::replace(&mut x.n, 0))
    }
    /// The station used up its lines for the current window: its other chatter stays quiet too.
    pub fn muted(&self, sta: &[u8; 6], now_ms: u64) -> bool {
        self.slot(sta).is_some_and(|i| self.e[i].lines >= self.burst && now_ms.wrapping_sub(self.e[i].win_ms) < Self::WINDOW_MS)
    }
    /// true once per station (streak): log the deauthentication failure detail.
    pub fn first_fail(&mut self, sta: &[u8; 6]) -> bool {
        self.slot(sta).is_some_and(|i| !core::mem::replace(&mut self.e[i].fail_logged, true))
    }
    /// The station keyed / left the streak: Some(events not yet logged) if it was in one.
    pub fn clear(&mut self, sta: &[u8; 6]) -> Option<u32> {
        let i = self.slot(sta)?;
        self.e[i].used = false;
        Some(self.e[i].n)
    }
}

/// Known-answer checks for the kernel (`[P-pmksa]`): parse (full / truncated-at-each-field / malformed / several
/// PMKIDs / RSNE behind other elements / fixed-field offsets) and the decision table.
pub fn selftest() -> bool {
    // RSNE: v1, group CCMP, 1 pairwise CCMP, 1 AKM SAE, caps 0x00cc, 2 PMKIDs, group mgmt BIP-CMAC
    let mut e = [0u8; 2 + 2 + 4 + 2 + 4 + 2 + 4 + 2 + 2 + 32 + 4];
    e[0] = 0x30;
    e[1] = (e.len() - 2) as u8;
    let b: [u8; 20] = [1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 8, 0xcc, 0];
    e[2..22].copy_from_slice(&b);
    e[22] = 2;
    for k in 0..32 {
        e[24 + k] = 0xa0 + k as u8;
    }
    e[56..60].copy_from_slice(&[0, 0x0f, 0xac, 6]);
    let mut ok = true;
    let mut ies = [0u8; 4 + 7 + 64];
    ies[0..7].copy_from_slice(&[0, 5, b'h', b'o', b'o', b'k', b'p']); // SSID first
    ies[7..7 + e.len()].copy_from_slice(&e);
    let n = 7 + e.len();
    let r = assoc_rsn(&ies[..n]);
    ok &= r.is_some_and(|r| r.akm == AKM_SAE && r.n_akm == 1 && r.n_pmkid == 2 && r.pmkid[1][0] == 0xb0 && r.pmkid[0][15] == 0xaf);
    // a whole request body (capability + listen interval first) still parses
    let mut body = [0u8; 4 + 4 + 7 + 64];
    body[0] = 0x31;
    body[4..4 + n].copy_from_slice(&ies[..n]);
    ok &= assoc_rsn(&body[..4 + n]) == r;
    // truncations: at each field boundary = valid; inside a field = malformed
    let body_len = e.len() - 2;
    for cut in 0..=body_len {
        let p = rsne_body(&e[2..2 + cut]);
        let boundary = matches!(cut, 2 | 6 | 12 | 18 | 20) || cut >= 54; // a started field / list must be complete
        ok &= p.is_some() == boundary;
    }
    ok &= rsne_body(&e[2..20]).is_some_and(|r| r.n_pmkid == 0 && r.akm == AKM_SAE);
    let mut bad = e;
    bad[2] = 2; // version 2
    ok &= rsne_body(&bad[2..]).is_none();
    bad = e;
    bad[22] = 9; // 9 PMKIDs claimed, 2 present
    ok &= rsne_body(&bad[2..]).is_none();
    ok &= find_rsne(&[0x30, 10, 1, 0]).is_none() && assoc_rsn(&[]).is_none() && assoc_rsn(&[0xdd]).is_none();
    // decision table
    let r = r.unwrap_or(AssocRsn { akm: 0, n_akm: 0, n_pmkid: 0, pmkid: [[0; 16]; PMKIDS] });
    let second = r.pmkid[1];
    let mut known = |p: &[u8; 16]| *p == second;
    let mut none = |_: &[u8; 16]| false;
    let all = OFFER_PSK | OFFER_SAE;
    ok &= decide(Some(&r), all, false, &mut known) == Keying::SaeCached(1);
    ok &= decide(Some(&r), OFFER_SAE, true, &mut known) == Keying::SaeFresh;
    ok &= decide(Some(&r), all, false, &mut none) == Keying::Reject;
    let psk = AssocRsn { akm: AKM_PSK, n_akm: 1, ..r };
    ok &= decide(Some(&psk), all, true, &mut known) == Keying::Psk;
    ok &= decide(Some(&psk), OFFER_PSK, false, &mut none) == Keying::Psk;
    ok &= decide(None, all, true, &mut known) == Keying::Legacy;
    ok &= decide(Some(&AssocRsn { n_akm: 2, ..r }), all, false, &mut none) == Keying::Legacy;
    ok &= decide(Some(&AssocRsn { akm: 0x000f_ac06, ..r }), all, false, &mut none) == Keying::Legacy;
    ok &= decide(Some(&AssocRsn { n_pmkid: 0, ..r }), all, false, &mut known) == Keying::SaeNoSae;
    // the metal case: a stale-scan station sends AKM 8 to a WPA2-only BSS (with or without SAE state) -> reason 20
    ok &= decide(Some(&AssocRsn { n_pmkid: 0, ..r }), OFFER_PSK, false, &mut none) == Keying::NotOffered;
    ok &= decide(Some(&r), OFFER_PSK, true, &mut known) == Keying::NotOffered;
    ok &= decide(Some(&psk), OFFER_SAE, false, &mut none) == Keying::NotOffered;
    ok &= Keying::NotOffered.reason() == Some(20) && Keying::SaeNoSae.reason() == Some(49);
    ok &= Keying::Reject.reason() == Some(49) && Keying::Psk.reason().is_none() && Keying::SaeCached(0).reason().is_none();
    ok && rejectlog_selftest()
}

fn rejectlog_selftest() -> bool {
    let mut l = RejectLog::new();
    let (a, b) = ([1u8; 6], [2u8; 6]);
    let w = RejectLog::WINDOW_MS;
    let mut ok = !l.muted(&a, 0) && l.note(&a, 1000) == Some(1) && l.muted(&a, 1001);
    ok &= l.first_fail(&a) && !l.first_fail(&a) && !l.first_fail(&b);
    for t in 1..=5u64 {
        ok &= l.note(&a, 1000 + t * 1000).is_none(); // quiet inside the window
    }
    ok &= l.note(&a, 1000 + w) == Some(6) && l.note(&a, 1001 + w).is_none() && l.clear(&a) == Some(1);
    ok &= l.clear(&a).is_none() && !l.muted(&a, 1002 + w) && l.note(&a, 1003 + w) == Some(1);
    // bounded: 20 stations fit in 8 slots, the newest is tracked
    for k in 0..20u8 {
        ok &= l.note(&[k, 9, 9, 9, 9, 9], 5 * w + k as u64) == Some(1);
    }
    ok &= l.muted(&[19, 9, 9, 9, 9, 9], 5 * w + 20);
    // burst 3 (the SAE trace): three lines, then quiet, then the count once the window turns
    let mut t = RejectLog::with_burst(3);
    ok &= t.note(&a, 0) == Some(1) && t.note(&a, 1) == Some(1) && t.note(&a, 2) == Some(1) && t.muted(&a, 2);
    ok &= t.note(&a, 3).is_none() && t.note(&a, 4).is_none() && t.muted(&a, 5);
    ok && t.note(&a, w) == Some(3) && !t.muted(&a, w)
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest() {
        assert!(super::selftest());
    }
}
