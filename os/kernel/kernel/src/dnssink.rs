//! M4 DNS-sinkhole / RPZ (Response Policy Zone) — "refuse a NAME, never a PACKET" (ADR 0023).
//!
//! heqk sits inline as a sensor/gateway. When a client queries a policy-blocked domain, the RPZ
//! engine returns a SINKHOLE answer (an A record pointing at a walled-garden IP) instead of the
//! real resolution — the *name* is refused, but the packet path is never dropped, so a legit
//! query for any other name flows untouched. This is the DNS analog of the enforcement-separation
//! rule: policy acts on the name, not by dropping traffic.
//!
//! Pure, bounds-safe, no_std, no heap, no I/O — the datapath wiring (intercept DNS responses on
//! the transiting flow) rides the control-plane transport; this module is the decision + the
//! crafted answer, unit-provable in QEMU. Query qnames NEVER use compression (RFC 1035 §4.1.4
//! pointers appear only in responses), so a 0xC0 length byte in a query is rejected fail-closed.

/// The compiled RPZ blocklist: a domain here (and all its subdomains) is sinkholed. Suffix match
/// on label boundaries (so `ads.example` blocks `x.ads.example` but not `notads.example`). In
/// production this is provisioned/updated over the authenticated control channel (like the reach
/// policy); here a small built-in corpus drives the gate.
const RPZ_LIST: &[&[u8]] = &[b"malware.example", b"ads.tracker", b"c2.evil.test"];

/// The sinkhole IPv4 (walled garden). Provisioned in production; a fixed local sentinel here.
pub const SINKHOLE_IP: [u8; 4] = [10, 200, 0, 254];

/// Extract the query's qname into `out` as lowercase dotted bytes (e.g. b"ads.tracker"), returning
/// its length. Bounds-safe + fail-closed: rejects truncation, an over-long name (>255), a label
/// >63, or a compression pointer (0xC0 — illegal in a query). Starts at the question section
/// (offset 12, after the 12-byte DNS header).
pub fn parse_qname(query: &[u8], out: &mut [u8; 256]) -> Option<usize> {
    if query.len() < 12 + 1 {
        return None;
    }
    let mut o = 12usize; // question section starts after the header
    let mut w = 0usize;
    loop {
        let len = *query.get(o)? as usize;
        if len == 0 {
            break; // root label terminates the name
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer (or reserved bits) — illegal in a query
        }
        if len > 63 {
            return None;
        }
        o += 1;
        if o + len > query.len() {
            return None; // label runs past the packet
        }
        if w != 0 {
            if w >= out.len() {
                return None;
            }
            out[w] = b'.';
            w += 1;
        }
        for i in 0..len {
            if w >= out.len() {
                return None;
            }
            let c = query[o + i];
            out[w] = c.to_ascii_lowercase();
            w += 1;
        }
        o += len;
        if w > 255 {
            return None; // RFC 1035 max name length
        }
    }
    Some(w)
}

/// Suffix-match `name` (lowercase dotted, from `parse_qname`) against the RPZ list on a label
/// boundary: an exact match, or `name` ends with `.blocked` (so a subdomain is caught, but a
/// name that merely ends in the same characters without a dot boundary is NOT).
pub fn rpz_blocked(name: &[u8]) -> bool {
    for &b in RPZ_LIST {
        if name == b {
            return true;
        }
        // subdomain: name = "<something>." ‖ b
        if name.len() > b.len() + 1 {
            let start = name.len() - b.len();
            if &name[start..] == b && name[start - 1] == b'.' {
                return true;
            }
        }
    }
    false
}

/// Craft a SINKHOLE DNS response for `query`: echo the ID + question, set QR=1/AA=1/RA=1,
/// ANCOUNT=1, and append one A record (name-compressed to the question at 0x0C, TYPE=A, CLASS=IN,
/// TTL, RDLENGTH=4, RDATA=`sinkhole`). Returns the response length in `out`, or `None` if the
/// query is malformed or `out` is too small. This is the answer the client receives for a blocked
/// name — the packet flowed; only the resolution is policy-controlled.
pub fn build_sinkhole_response(query: &[u8], sinkhole: [u8; 4], out: &mut [u8]) -> Option<usize> {
    // Locate the end of the question (after the qname 0-terminator + QTYPE(2) + QCLASS(2)).
    if query.len() < 12 + 1 {
        return None;
    }
    let mut o = 12usize;
    loop {
        let len = *query.get(o)? as usize;
        if len & 0xC0 != 0 {
            return None;
        }
        o += 1;
        if len == 0 {
            break;
        }
        o += len;
        if o > query.len() {
            return None;
        }
    }
    let qend = o.checked_add(4)?; // + QTYPE + QCLASS
    if qend > query.len() {
        return None;
    }
    let total = qend + 16; // + one A RR (ptr2 + type2 + class2 + ttl4 + rdlen2 + rdata4)
    if total > out.len() {
        return None;
    }
    out[..qend].copy_from_slice(&query[..qend]);
    // Flags: QR=1, Opcode=0, AA=1, TC=0, RD(echo), RA=1; RCODE=0.
    out[2] = 0x85; // 1000 0101 = QR|AA|RD
    out[3] = 0x80; // RA
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    out[8..12].copy_from_slice(&[0, 0, 0, 0]); // NS/AR = 0
    let a = qend;
    out[a] = 0xC0;
    out[a + 1] = 0x0C; // name = pointer to the question qname at offset 12
    out[a + 2..a + 4].copy_from_slice(&1u16.to_be_bytes()); // TYPE=A
    out[a + 4..a + 6].copy_from_slice(&1u16.to_be_bytes()); // CLASS=IN
    out[a + 6..a + 10].copy_from_slice(&60u32.to_be_bytes()); // TTL=60
    out[a + 10..a + 12].copy_from_slice(&4u16.to_be_bytes()); // RDLENGTH=4
    out[a + 12..a + 16].copy_from_slice(&sinkhole);
    Some(total)
}

// ---- Shield (AP): answer a client's query for a blocked name directly ----------------------------

fn csum(b: &[u8], init: u32) -> u16 {
    let mut s = init;
    let mut i = 0;
    while i + 1 < b.len() {
        s += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        s += (b[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// A client's Ethernet/IPv4/UDP DNS query (any destination resolver) whose qname `blocked` refuses →
/// the answer frame in `out`, sent back to the client as if from the resolver it asked: QTYPE A → one
/// A record 0.0.0.0 (TTL 60), any other type → NOERROR with no answer (NODATA). None = not a DNS
/// query, malformed, fragmented, a response, or a name that is not blocked (forward as usual).
pub fn block_reply_frame(f: &[u8], me: &[u8; 6], out: &mut [u8], blocked: &dyn Fn(&[u8]) -> bool) -> Option<usize> {
    if f.len() < 14 + 20 + 8 + 12 || f[12..14] != [0x08, 0x00] || f[14] >> 4 != 4 || f[23] != 17 {
        return None;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    let tot = u16::from_be_bytes([f[16], f[17]]) as usize;
    if ihl < 20 || tot < ihl + 8 || 14 + tot > f.len() || u16::from_be_bytes([f[20], f[21]]) & 0x3fff != 0 {
        return None; // bad lengths, or a fragment
    }
    let u = 14 + ihl;
    if u16::from_be_bytes([f[u + 2], f[u + 3]]) != 53 {
        return None;
    }
    let ulen = u16::from_be_bytes([f[u + 4], f[u + 5]]) as usize;
    if ulen < 8 + 12 || u + ulen > 14 + tot {
        return None;
    }
    let q = &f[u + 8..u + ulen];
    // a standard query (QR=0, opcode 0) with exactly one question
    if q[2] & 0xf8 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut name = [0u8; 256];
    let nl = parse_qname(q, &mut name)?;
    if !blocked(&name[..nl]) {
        return None;
    }
    // end of the question: qname wire length + QTYPE + QCLASS
    let mut o = 12usize;
    loop {
        let l = *q.get(o)? as usize;
        o += 1;
        if l == 0 {
            break;
        }
        o += l;
    }
    let qend = o + 4;
    if qend > q.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([q[o], q[o + 1]]);
    let qclass = u16::from_be_bytes([q[o + 2], q[o + 3]]);
    let a = qtype == 1 && qclass == 1;
    let dlen = qend + if a { 16 } else { 0 };
    let total = 14 + 20 + 8 + dlen;
    if total > out.len() {
        return None;
    }
    // Ethernet: back to the client, from us
    out[0..6].copy_from_slice(&f[6..12]);
    out[6..12].copy_from_slice(me);
    out[12..14].copy_from_slice(&[0x08, 0x00]);
    // IPv4 (no options), from the resolver the client asked
    let ip = &mut out[14..34];
    ip.copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    ip[2..4].copy_from_slice(&((20 + 8 + dlen) as u16).to_be_bytes());
    ip[12..16].copy_from_slice(&f[30..34]);
    ip[16..20].copy_from_slice(&f[26..30]);
    let c = csum(&out[14..34], 0);
    out[24..26].copy_from_slice(&c.to_be_bytes());
    // UDP
    out[34..36].copy_from_slice(&53u16.to_be_bytes());
    out[36..38].copy_from_slice(&f[u..u + 2]);
    out[38..40].copy_from_slice(&((8 + dlen) as u16).to_be_bytes());
    out[40..42].copy_from_slice(&[0, 0]);
    // DNS
    let d = &mut out[42..42 + dlen];
    d[..qend].copy_from_slice(&q[..qend]);
    d[2] = 0x80 | (q[2] & 0x01); // QR, RD echoed
    d[3] = 0x80; // RA, RCODE 0
    d[6..8].copy_from_slice(&(a as u16).to_be_bytes());
    d[8..12].copy_from_slice(&[0, 0, 0, 0]);
    if a {
        d[qend..qend + 16].copy_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 0, 0, 0, 0]);
    }
    let mut ps = 17u32 + (8 + dlen) as u32;
    for k in (26..34).step_by(2) {
        ps += u16::from_be_bytes([out[k], out[k + 1]]) as u32;
    }
    let mut uc = csum(&out[34..34 + 8 + dlen], ps);
    if uc == 0 {
        uc = 0xffff;
    }
    out[40..42].copy_from_slice(&uc.to_be_bytes());
    Some(total)
}

/// Selftest helper: an Ethernet/IPv4/UDP query client 10.99.0.10:5353 -> 10.99.0.1:53 for `name`.
pub fn test_query_frame(name: &[u8], qtype: u16, out: &mut [u8]) -> usize {
    let mut d = [0u8; 300];
    d[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    d[2] = 0x01; // RD
    d[5] = 1;
    let mut o = 12;
    for label in name.split(|&c| c == b'.') {
        d[o] = label.len() as u8;
        d[o + 1..o + 1 + label.len()].copy_from_slice(label);
        o += 1 + label.len();
    }
    d[o] = 0;
    o += 1;
    d[o..o + 4].copy_from_slice(&[(qtype >> 8) as u8, qtype as u8, 0, 1]);
    o += 4;
    let total = 42 + o;
    out[..14].copy_from_slice(&[2, 0, 0, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0, 0, 0x10, 0x08, 0x00]);
    out[14..34].copy_from_slice(&[0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 10, 99, 0, 10, 10, 99, 0, 1]);
    out[16..18].copy_from_slice(&((20 + 8 + o) as u16).to_be_bytes());
    out[34..36].copy_from_slice(&5353u16.to_be_bytes());
    out[36..38].copy_from_slice(&53u16.to_be_bytes());
    out[38..40].copy_from_slice(&((8 + o) as u16).to_be_bytes());
    out[40..42].copy_from_slice(&[0, 0]);
    out[42..total].copy_from_slice(&d[..o]);
    total
}

/// Selftest helper: `r` is a well-formed answer to `q` (addresses/ports swapped, checksums valid,
/// same id and question).
pub fn reply_frame_ok(q: &[u8], r: &[u8], me: &[u8; 6]) -> bool {
    if r.len() < 54 || r[0..6] != q[6..12] || &r[6..12] != me || r[26..30] != q[30..34] || r[30..34] != q[26..30] {
        return false;
    }
    let ulen = u16::from_be_bytes([r[38], r[39]]) as usize;
    let mut ps = 17u32 + ulen as u32;
    for k in (26..34).step_by(2) {
        ps += u16::from_be_bytes([r[k], r[k + 1]]) as u32;
    }
    csum(&r[14..34], 0) == 0 && 34 + ulen == r.len() && csum(&r[34..34 + ulen], ps) == 0
        && r[34..36] == [0, 53] && r[36..38] == q[34..36] && r[42..44] == q[42..44] && r[46..48] == [0, 1] && r[44] & 0x80 != 0
}
