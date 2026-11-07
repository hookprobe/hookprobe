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
