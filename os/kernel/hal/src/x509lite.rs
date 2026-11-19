// SPDX-License-Identifier: AGPL-3.0-only
//! L-02: the facts Mission Control shows about its own certificate (names, addresses, expiry), read from the leaf
//! DER the device serves. A bounded DER walk — never a validator (the browser validates; this only reports).
//! Every length is checked against its parent; anything malformed yields `None`.

/// One TLV at `p[i..]`: (tag, content start, content end).
fn tlv(p: &[u8], i: usize) -> Option<(u8, usize, usize)> {
    let tag = *p.get(i)?;
    let l0 = *p.get(i + 1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 3 {
            return None;
        }
        let mut v = 0usize;
        for k in 0..n {
            v = (v << 8) | *p.get(i + 2 + k)? as usize;
        }
        (v, 2 + n)
    };
    let s = i + hdr;
    let e = s.checked_add(len)?;
    if e > p.len() {
        return None;
    }
    Some((tag, s, e))
}

pub const NAMES_MAX: usize = 4;
pub const IPS_MAX: usize = 6;

/// What the certificate covers and until when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub names: [([u8; 63], u8); NAMES_MAX],
    pub n_names: usize,
    pub ips: [[u8; 4]; IPS_MAX],
    pub n_ips: usize,
    /// notAfter as printed in the certificate (UTCTime `YYMMDDhhmmssZ` or GeneralizedTime), ASCII.
    pub not_after: ([u8; 15], u8),
}

impl Default for Facts {
    fn default() -> Self {
        Facts { names: [([0; 63], 0); NAMES_MAX], n_names: 0, ips: [[0; 4]; IPS_MAX], n_ips: 0, not_after: ([0; 15], 0) }
    }
}

impl Facts {
    pub fn name(&self, i: usize) -> &[u8] {
        &self.names[i].0[..self.names[i].1 as usize]
    }
    /// Does the certificate cover `host` (a DNS name, case-insensitive, or a dotted IPv4, port already removed)?
    pub fn covers(&self, host: &[u8]) -> bool {
        if (0..self.n_names).any(|i| self.name(i).eq_ignore_ascii_case(host)) {
            return true;
        }
        parse_v4(host).is_some_and(|a| self.ips[..self.n_ips].contains(&a))
    }
}

fn parse_v4(s: &[u8]) -> Option<[u8; 4]> {
    let mut o = [0u8; 4];
    let mut k = 0;
    for part in s.split(|&c| c == b'.') {
        if k == 4 || part.is_empty() || part.len() > 3 || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let v = part.iter().fold(0u32, |a, &c| a * 10 + (c - b'0') as u32);
        if v > 255 {
            return None;
        }
        o[k] = v as u8;
        k += 1;
    }
    (k == 4).then_some(o)
}

const OID_SAN: [u8; 3] = [0x55, 0x1d, 0x11];

/// The facts of one leaf certificate (DER).
pub fn facts(der: &[u8]) -> Option<Facts> {
    let mut f = Facts::default();
    let (t, cs, ce) = tlv(der, 0)?; // Certificate
    if t != 0x30 {
        return None;
    }
    let (t, ts, te) = tlv(der, cs)?; // tbsCertificate
    if t != 0x30 || te > ce {
        return None;
    }
    let mut i = ts;
    let mut field = 0;
    while i < te {
        let (t, s, e) = tlv(der, i)?;
        if t == 0xa0 && field == 0 {
            i = e; // [0] version: not a numbered field below
            continue;
        }
        // fields: 0 serial, 1 signature, 2 issuer, 3 validity, 4 subject, 5 spki, then [1] [2] [3]
        if field == 3 && t == 0x30 {
            let (_, _, nb_e) = tlv(der, s)?;
            let (t2, ns, ne) = tlv(der, nb_e)?;
            if (t2 == 0x17 || t2 == 0x18) && ne - ns <= 15 {
                f.not_after.0[..ne - ns].copy_from_slice(&der[ns..ne]);
                f.not_after.1 = (ne - ns) as u8;
            }
        }
        if t == 0xa3 {
            let (t2, xs, xe) = tlv(der, s)?; // SEQUENCE OF Extension
            if t2 != 0x30 {
                return None;
            }
            let mut j = xs;
            while j < xe {
                let (_, es, ee) = tlv(der, j)?;
                let (ot, os, oe) = tlv(der, es)?;
                if ot == 0x06 && der[os..oe] == OID_SAN {
                    // [critical BOOLEAN] then OCTET STRING { SEQUENCE OF GeneralName }
                    let mut k = oe;
                    let (mut vt, mut vs, mut ve) = tlv(der, k)?;
                    if vt == 0x01 {
                        k = ve;
                        (vt, vs, ve) = tlv(der, k)?;
                    }
                    if vt != 0x04 {
                        return None;
                    }
                    let (st, ss, se) = tlv(der, vs)?;
                    if st != 0x30 || se > ve {
                        return None;
                    }
                    let mut g = ss;
                    while g < se {
                        let (gt, gs, ge) = tlv(der, g)?;
                        match gt {
                            0x82 if f.n_names < NAMES_MAX && ge - gs <= 63 => {
                                f.names[f.n_names].0[..ge - gs].copy_from_slice(&der[gs..ge]);
                                f.names[f.n_names].1 = (ge - gs) as u8;
                                f.n_names += 1;
                            }
                            0x87 if ge - gs == 4 && f.n_ips < IPS_MAX => {
                                f.ips[f.n_ips].copy_from_slice(&der[gs..ge]);
                                f.n_ips += 1;
                            }
                            _ => {}
                        }
                        g = ge;
                    }
                }
                j = ee;
            }
        }
        field += 1;
        i = e;
    }
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    const BENCH: &[u8] = include_bytes!("../testdata/mctls-bench.der");

    #[test]
    fn reads_the_bench_certificate() {
        let f = facts(BENCH).unwrap();
        assert_eq!(f.n_names, 2);
        assert_eq!(f.name(0), b"heqk.local");
        assert_eq!(f.name(1), b"r3q1.heqk.local");
        assert_eq!(&f.ips[..f.n_ips], &[[10, 99, 0, 1], [192, 168, 200, 146], [10, 200, 0, 6]]);
        assert_eq!(&f.not_after.0[..f.not_after.1 as usize], b"271219115621Z");
        assert!(f.covers(b"HEQK.local") && f.covers(b"r3q1.heqk.local") && f.covers(b"192.168.200.146"));
        assert!(!f.covers(b"192.168.200.147") && !f.covers(b"evil.heqk.local") && !f.covers(b"1.2.3"));
    }

    #[test]
    fn malformed_input_is_none() {
        assert!(facts(&[]).is_none());
        assert!(facts(&BENCH[..100]).is_none());
        let mut b = BENCH.to_vec();
        b[1] = 0x85; // a 5-byte length form
        assert!(facts(&b).is_none());
    }
}
