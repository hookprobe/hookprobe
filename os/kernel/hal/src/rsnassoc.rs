//! The station's RSNE from its (Re)Association Request — attacker-shaped bytes from anyone in radio range — and the
//! AP's keying decision (IEEE 802.11-2020 12.6.10.3 / 12.7, what hostapd's `wpa_validate_wpa_ie` decides).
//!
//! The CYW43455 FullMAC firmware answers the association itself and then raises WLC_E_ASSOC_IND / REASSOC_IND whose
//! event data is the request's information elements (brcmfmac hands exactly that buffer to cfg80211 as
//! `assoc_req_ies`). The AP's host authenticator must key the 4-way with the AKM the STATION chose there:
//! - AKM 8 (SAE) right after a full SAE exchange -> that SAE PMK;
//! - AKM 8 with a PMKID we hold for this station (PMKSA caching, open-system auth, no SAE) -> the cached PMK;
//! - AKM 8 with no PMKID we know -> refuse (the station must redo SAE; keying it as PSK can never succeed);
//! - AKM 2 (PSK) -> the passphrase PMK.
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
    /// AKM 8 with no PMKSA we hold: refuse (deauthenticate, reason 49 invalid PMKID) so the station redoes SAE.
    Reject,
}

impl Keying {
    pub fn name(&self) -> &'static str {
        match self {
            Keying::Legacy => "no readable RSNE: previous rule",
            Keying::Psk => "PSK",
            Keying::SaeFresh => "SAE (just authenticated)",
            Keying::SaeCached(_) => "SAE (cached PMKSA)",
            Keying::Reject => "SAE with an unknown PMKID: reject",
        }
    }
}

/// Reason code 49: invalid PMKID (IEEE 802.11-2020 Table 9-49).
pub const REASON_INVALID_PMKID: u16 = 49;

/// The keying decision. `fresh_sae` = this station completed SAE within the responder TTL; `known` = a PMKID that a
/// cached PMKSA of this station carries.
pub fn decide(rsn: Option<&AssocRsn>, fresh_sae: bool, known: &mut dyn FnMut(&[u8; 16]) -> bool) -> Keying {
    let Some(r) = rsn else { return Keying::Legacy };
    if r.n_akm != 1 {
        return Keying::Legacy;
    }
    match r.akm {
        AKM_PSK => Keying::Psk,
        AKM_SAE if fresh_sae => Keying::SaeFresh,
        AKM_SAE => r.pmkids().iter().position(|p| known(p)).map_or(Keying::Reject, Keying::SaeCached),
        _ => Keying::Legacy,
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
    ok &= decide(Some(&r), false, &mut known) == Keying::SaeCached(1);
    ok &= decide(Some(&r), true, &mut known) == Keying::SaeFresh;
    ok &= decide(Some(&r), false, &mut none) == Keying::Reject;
    let psk = AssocRsn { akm: AKM_PSK, n_akm: 1, ..r };
    ok &= decide(Some(&psk), true, &mut known) == Keying::Psk;
    ok &= decide(None, true, &mut known) == Keying::Legacy;
    ok &= decide(Some(&AssocRsn { n_akm: 2, ..r }), false, &mut none) == Keying::Legacy;
    ok &= decide(Some(&AssocRsn { akm: 0x000f_ac06, ..r }), false, &mut none) == Keying::Legacy;
    ok &= decide(Some(&AssocRsn { n_pmkid: 0, ..r }), false, &mut known) == Keying::Reject;
    ok
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest() {
        assert!(super::selftest());
    }
}
