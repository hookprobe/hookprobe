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
    /// The station's first join within `STALE_WINDOW_MS` of a live security change, with an AKM the PREVIOUS BSS also
    /// offered: it may be keying from its scan of the previous BSS (and will drop our M3, whose RSNE is the new one).
    /// Refuse once before M1 (reason 2, hostapd's reason on a configuration reload) so it rescans. See `StaleGuard`.
    StaleView,
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
            Keying::StaleView => "stale view after a live security change: refused once to rescan",
        }
    }
    /// The deauthentication reason for a refusal; None = key the 4-way.
    pub fn reason(&self) -> Option<u16> {
        match self {
            Keying::Reject | Keying::SaeNoSae => Some(REASON_INVALID_PMKID),
            Keying::NotOffered => Some(REASON_INVALID_AKMP),
            Keying::StaleView => Some(REASON_PREV_AUTH_NOT_VALID),
            _ => None,
        }
    }
}

/// Reason code 49: invalid PMKID (IEEE 802.11-2020 Table 9-49).
pub const REASON_INVALID_PMKID: u16 = 49;
/// Reason code 20: invalid AKMP.
pub const REASON_INVALID_AKMP: u16 = 20;
/// Reason code 2: previous authentication no longer valid (hostapd deauthenticates every station with it when its
/// configuration is reloaded).
pub const REASON_PREV_AUTH_NOT_VALID: u16 = 2;
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

/// How long after a live security change a station's first join is treated as possibly keyed from a stale scan:
/// cfg80211 keeps a BSS entry 30 s (IEEE80211_SCAN_RESULT_EXPIRE), and wpa_supplicant's fast reconnect reuses it.
pub const STALE_WINDOW_MS: u64 = 30_000;

/// The live-security-change guard (metal MB11, 2026-11-12). After a live WPA2 -> WPA3-transition bounce the bench Pi
/// re-associated within a second with AKM 2 (PSK) — an AKM a fresh scan of a transition BSS would not have made it
/// choose (its profile offers SAE, and every fresh join keyed `akm=SAE`) — got M1, sent a valid M2, got M3 and left
/// without M4: wpa_supplicant compares the M3 RSNE byte for byte with the RSNE of ITS copy of the beacon, and that
/// copy was the previous WPA2 BSS's (reason 17 "IE in 4-way differs"), then counted it as a wrong key and backed off
/// for minutes. The same M3 RSNE keyed every fresh-scan join of the same image, so M3 is right and must stay the new
/// BSS's (sending the old RSNE would defeat the downgrade check it exists for). The AP-side fix: refuse such a
/// station once BEFORE M1 — a deauthentication before the 4-way is not a key failure for the station, and with no
/// completed connection to fast-reconnect to it rescans, sees the BSS as it is now and joins with the right AKM.
/// Only an AKM the previous BSS offered is suspect (a station joining with an AKM only the new BSS offers saw the new
/// one); each station at most once per change; bounded (a full table keys normally, the earlier behaviour).
pub struct StaleGuard {
    at_ms: u64,
    prev: u8,
    armed: bool,
    seen: [u64; 8],
    n: u8,
}

impl Default for StaleGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl StaleGuard {
    pub const fn new() -> StaleGuard {
        StaleGuard { at_ms: 0, prev: 0, armed: false, seen: [0; 8], n: 0 }
    }
    /// A live security change from offers `prev` to `now` (OFFER_* bits) at `now_ms`. The same offers (a self-heal
    /// bounce) leave every station's view valid: nothing to guard.
    pub fn arm(&mut self, prev: u8, now: u8, now_ms: u64) {
        *self = StaleGuard { at_ms: now_ms, prev, armed: prev != now, seen: [0; 8], n: 0 };
    }
    /// Is the guard window open?
    pub fn active(&self, now_ms: u64) -> bool {
        self.armed && now_ms.wrapping_sub(self.at_ms) < STALE_WINDOW_MS
    }
    /// true = refuse this station's keying once (`Keying::StaleView`); `akm` = the AKM of its association RSNE.
    pub fn check(&mut self, sta: &[u8; 6], akm: u32, now_ms: u64) -> bool {
        if !self.active(now_ms) {
            self.armed = false;
            return false;
        }
        let bit = match akm {
            AKM_PSK => OFFER_PSK,
            AKM_SAE => OFFER_SAE,
            _ => return false,
        };
        let k = mac64(sta);
        let n = self.n as usize;
        if self.prev & bit == 0 || self.seen[..n].contains(&k) || n >= self.seen.len() {
            return false;
        }
        self.seen[n] = k;
        self.n += 1;
        true
    }
}

/// A station-leave event within this long of the same station's SAE Accepted is not allowed to undo it (metal MB11
/// house check: 58 SAE Accepted + auth_status OK, then 87 association rejects with status 16 — a leave of the
/// station's previous attempt, processed after the new SAE, wiped the PMKSA auth_status had just installed and the
/// host SAE state; the firmware then treats the association as if no SAE completed). A station associates within
/// milliseconds of its SAE confirm; a genuine leave in this window only costs the SAE state its TTL.
pub const LEAVE_GRACE_MS: u64 = 2_000;

/// WLC_SCB_DEAUTHENTICATE_FOR_REASON's argument, brcmf_scb_val_le {__le32 val; u8 ea[6]}: 12 bytes with the struct's
/// tail padding (C sizeof, what brcmfmac sends). The 10-byte form was refused BCME_BUFTOOSHORT (-14) on every call
/// (metal MB13: all 18 deauthentications fell back to 143, which sends no reason).
pub fn scb_val(reason: u16, sta: &[u8; 6]) -> [u8; 12] {
    let mut v = [0u8; 12];
    v[0..2].copy_from_slice(&reason.to_le_bytes());
    v[4..10].copy_from_slice(sta);
    v
}

/// How long an SAE completion is watched for the station's association before the AP logs that none came (with the
/// auth_status timing and the firmware console) — a station associates within milliseconds of our confirm.
pub const SAE_WATCH_MS: u64 = 2_000;

/// Does a leave event of a station whose host SAE state is `accepted` (SAE confirm verified, not yet keyed / left),
/// `age_ms` after that Accepted, belong to an EARLIER attempt (ignore it for the SAE / PMKSA state)?
pub fn leave_predates_sae(accepted: bool, age_ms: u64) -> bool {
    accepted && age_ms < LEAVE_GRACE_MS
}

/// The firmware's PMKSA list (`pmkid_info` is replaced WHOLE on every set: brcmf_pmksa_v1 {npmk, {bssid, pmkid}[]}),
/// mirrored on the host so one station's PMKSA is added or dropped without touching the others'. Bounded: a full list
/// replaces the oldest entry.
pub struct FwPmksa {
    e: [([u8; 6], [u8; 16]); FwPmksa::MAX],
    n: u8,
}

impl Default for FwPmksa {
    fn default() -> Self {
        Self::new()
    }
}

impl FwPmksa {
    pub const MAX: usize = 8;
    pub const fn new() -> FwPmksa {
        FwPmksa { e: [([0; 6], [0; 16]); FwPmksa::MAX], n: 0 }
    }
    pub fn len(&self) -> usize {
        self.n as usize
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    /// Add / replace `sta`'s PMKSA (moved to the newest place).
    pub fn put(&mut self, sta: &[u8; 6], pmkid: &[u8; 16]) {
        self.remove(sta);
        if self.len() == Self::MAX {
            self.e.copy_within(1.., 0);
            self.n -= 1;
        }
        self.e[self.len()] = (*sta, *pmkid);
        self.n += 1;
    }
    /// Drop `sta`'s PMKSA; true if it had one.
    pub fn remove(&mut self, sta: &[u8; 6]) -> bool {
        let n = self.len();
        match (0..n).find(|&i| self.e[i].0 == *sta) {
            Some(i) => {
                self.e.copy_within(i + 1..n, i);
                self.e[n - 1] = ([0; 6], [0; 16]);
                self.n -= 1;
                true
            }
            None => false,
        }
    }
    pub fn clear(&mut self) {
        *self = FwPmksa::new();
    }
    /// The `pmkid_info` payload: le32 count ‖ {peer[6], pmkid[16]} per entry. `out` >= 4 + 22 * MAX.
    pub fn encode(&self, out: &mut [u8]) -> usize {
        out[..4].copy_from_slice(&(self.n as u32).to_le_bytes());
        let mut k = 4;
        for (m, p) in &self.e[..self.len()] {
            out[k..k + 6].copy_from_slice(m);
            out[k + 6..k + 22].copy_from_slice(p);
            k += 22;
        }
        k
    }
}

/// `auth_status` variants (flags, with SSID) in trial order — the one this firmware accepted last time first (metal:
/// variant 0 refused BCME -2 on every SAE before variant 1 was taken, one wasted control round-trip each time).
pub fn auth_status_order(known: Option<usize>) -> [usize; 4] {
    match known {
        Some(k) if k < 4 => {
            let mut o = [k, 0, 0, 0];
            let mut j = 1;
            for i in 0..4 {
                if i != k {
                    o[j] = i;
                    j += 1;
                }
            }
            o
        }
        _ => [0, 1, 2, 3],
    }
}

/// The RSNE ‖ RSNXE the CYW43455 firmware beacons for a WPA3 mode, built from the mode the AP just installed — what M3
/// repeats when the firmware's own beacon IEs cannot be read back (WLC_GET_BSS_INFO does not return them in AP mode:
/// metal batch 45). Pinned from the metal captures (wpa_supplicant debug, batches 42-44 and 47): group + pairwise
/// CCMP; transition = AKMs PSK then SAE, SAE-only = AKM 8 alone; caps = 16 PTKSA replay counters (0x0c) | MFPC (0x80)
/// if `mfp` >= 1 | MFPR (0x40) if `mfp` == 2, `mfp` as the firmware reports it after bring-up; no group management
/// suite (BIP-CMAC-128 is the default); then the RSNXE `f4 01 20` (SAE hash-to-element). `out` >= 32 bytes.
/// transition, mfp 1: `30 18 0100 000fac04 0100 000fac04 0200 000fac02 000fac08 8c00 f40120`
/// SAE only,   mfp 2: `30 14 0100 000fac04 0100 000fac04 0100 000fac08 cc00 f40120`
pub fn wpa3_beacon_rsne(transition: bool, mfp: u32, out: &mut [u8]) -> usize {
    let caps: u8 = 0x0c | if mfp >= 1 { 0x80 } else { 0 } | if mfp >= 2 { 0x40 } else { 0 };
    let head = [0x30, 0, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04];
    out[..head.len()].copy_from_slice(&head);
    let mut n = head.len();
    let akms: &[u8] = if transition {
        &[0x02, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x0f, 0xac, 0x08]
    } else {
        &[0x01, 0x00, 0x00, 0x0f, 0xac, 0x08]
    };
    out[n..n + akms.len()].copy_from_slice(akms);
    n += akms.len();
    out[n] = caps;
    out[n + 1] = 0;
    n += 2;
    out[1] = (n - 2) as u8;
    out[n..n + 3].copy_from_slice(&[0xf4, 0x01, 0x20]);
    n + 3
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
impl Default for RejectLog {
    fn default() -> Self {
        Self::new()
    }
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
    ok &= Keying::StaleView.reason() == Some(2);
    ok && rejectlog_selftest() && staleguard_selftest() && beacon_rsne_selftest() && pmksa_list_selftest()
}

fn staleguard_selftest() -> bool {
    let (a, b) = ([1u8; 6], [2u8; 6]);
    let (p, s, both) = (OFFER_PSK, OFFER_SAE, OFFER_PSK | OFFER_SAE);
    let mut g = StaleGuard::new();
    // never armed (boot): nothing refused
    let mut ok = !g.check(&a, AKM_PSK, 0);
    // the metal case: WPA2 -> transition; the PSK station is refused once, then keys; SAE (new-only AKM) never
    g.arm(p, both, 1000);
    ok &= g.check(&a, AKM_PSK, 1500) && !g.check(&a, AKM_PSK, 2500);
    ok &= !g.check(&b, AKM_SAE, 1600) && g.check(&b, AKM_PSK, 1700);
    ok &= !g.check(&[3; 6], 0x000f_ac06, 1800); // another AKM: not judged
    // the window closes
    g.arm(p, both, 1000);
    ok &= !g.check(&a, AKM_PSK, 1000 + STALE_WINDOW_MS) && !g.check(&b, AKM_PSK, 1001);
    // transition -> WPA2: PSK suspect (the old BSS offered it); transition -> SAE only: SAE suspect
    g.arm(both, p, 0);
    ok &= g.check(&a, AKM_PSK, 1);
    g.arm(both, s, 0);
    ok &= g.check(&a, AKM_SAE, 1);
    // SAE only -> transition: only SAE suspect
    g.arm(s, both, 0);
    ok &= !g.check(&a, AKM_PSK, 1) && g.check(&b, AKM_SAE, 1);
    // a same-mode bounce (self-heal): not armed
    g.arm(both, both, 0);
    ok &= !g.active(1) && !g.check(&a, AKM_PSK, 1);
    // bounded: 8 stations refused, the 9th keys normally
    g.arm(p, both, 0);
    for k in 0..8u8 {
        ok &= g.check(&[k, 7, 7, 7, 7, 7], AKM_PSK, 2);
    }
    ok && !g.check(&[9, 7, 7, 7, 7, 7], AKM_PSK, 3)
}

fn pmksa_list_selftest() -> bool {
    let (a, b, c) = ([1u8; 6], [2u8; 6], [3u8; 6]);
    let mut l = FwPmksa::new();
    let mut o = [0u8; 4 + 22 * FwPmksa::MAX];
    let mut ok = l.encode(&mut o) == 4 && o[..4] == [0, 0, 0, 0];
    l.put(&a, &[0xa; 16]);
    l.put(&b, &[0xb; 16]);
    l.put(&a, &[0xc; 16]); // replaced, not duplicated
    ok &= l.len() == 2 && l.encode(&mut o) == 48 && o[0] == 2 && o[4..10] == b && o[26..32] == a && o[32] == 0xc;
    // dropping one station's PMKSA keeps the other's (the house-check defect: a leave wiped the whole list)
    ok &= l.remove(&a) && !l.remove(&c) && l.len() == 1 && l.encode(&mut o) == 26 && o[4..10] == b && o[10] == 0xb;
    // bounded: the oldest goes
    for k in 0..10u8 {
        l.put(&[k, 5, 5, 5, 5, 5], &[k; 16]);
    }
    ok &= l.len() == FwPmksa::MAX && l.encode(&mut o) == 4 + 22 * FwPmksa::MAX && o[4] == 2 && o[4 + 22 * 7] == 9;
    l.clear();
    ok &= l.is_empty();
    // a leave right after the station's SAE Accepted belongs to its earlier attempt
    ok &= leave_predates_sae(true, 0) && leave_predates_sae(true, LEAVE_GRACE_MS - 1);
    ok &= !leave_predates_sae(true, LEAVE_GRACE_MS) && !leave_predates_sae(false, 0);
    // 201's argument: reason LE32, the MAC, 2 bytes of tail padding
    ok &= scb_val(2, &[1, 2, 3, 4, 5, 6]) == [2, 0, 0, 0, 1, 2, 3, 4, 5, 6, 0, 0];
    // auth_status: the accepted variant first, the rest in order
    ok && auth_status_order(None) == [0, 1, 2, 3] && auth_status_order(Some(1)) == [1, 0, 2, 3]
        && auth_status_order(Some(3)) == [3, 0, 1, 2] && auth_status_order(Some(7)) == [0, 1, 2, 3]
}

fn beacon_rsne_selftest() -> bool {
    let mut o = [0u8; 40];
    // batch 42/43 wpa_supplicant capture: the 5 GHz transition beacon RSNE ‖ RSNXE
    let t: [u8; 29] = [0x30, 0x18, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 2, 0, 0, 0x0f, 0xac, 2, 0, 0x0f, 0xac, 8, 0x8c, 0, 0xf4, 1, 0x20];
    let mut ok = wpa3_beacon_rsne(true, 1, &mut o) == t.len() && o[..t.len()] == t;
    // batch 47: SAE only, caps cc 00
    let w: [u8; 25] = [0x30, 0x14, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 8, 0xcc, 0, 0xf4, 1, 0x20];
    ok &= wpa3_beacon_rsne(false, 2, &mut o) == w.len() && o[..w.len()] == w;
    // mfp off (read back 0): no MFP bits
    ok &= wpa3_beacon_rsne(true, 0, &mut o) == t.len() && o[24] == 0x0c;
    // the RSNE parses as a station would, and the length byte covers exactly the RSNE
    let n = wpa3_beacon_rsne(true, 1, &mut o);
    ok && find_rsne(&o[..n]).is_some_and(|b| b.len() == 0x18) && rsne_body(&o[2..2 + 0x18]).is_some_and(|r| r.n_akm == 2 && r.akm == AKM_PSK)
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
