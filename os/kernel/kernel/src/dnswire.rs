//! Pure DNS wire parsing (names with compression, the client query) — moved verbatim from `shield.rs` (SEC-02) so
//! the host libFuzzer harness compiles the same code. Every byte is from the network.

/// A decoded name (lowercase dotted, no trailing dot). Compression-aware for responses; `allow_ptr` false
/// for questions in queries (a pointer there is malformed).
pub fn read_name(msg: &[u8], mut o: usize, out: &mut [u8; 256], allow_ptr: bool) -> Option<(usize, usize)> {
    let mut w = 0usize;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(o)? as usize;
        if len & 0xC0 == 0xC0 {
            if !allow_ptr || jumps >= 16 {
                return None;
            }
            let p = ((len & 0x3F) << 8) | *msg.get(o + 1)? as usize;
            if end.is_none() {
                end = Some(o + 2);
            }
            if p >= o {
                return None; // pointers only go backwards (no loops)
            }
            o = p;
            jumps += 1;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if len == 0 {
            return Some((w, end.unwrap_or(o + 1)));
        }
        let lab = msg.get(o + 1..o + 1 + len)?;
        if w != 0 {
            *out.get_mut(w)? = b'.';
            w += 1;
        }
        if w + len > 253 {
            return None;
        }
        for (i, &c) in lab.iter().enumerate() {
            out[w + i] = c.to_ascii_lowercase();
        }
        w += len;
        o += 1 + len;
    }
}

/// A parsed client query: the DNS message slice bounds + question facts.
pub struct Q {
    pub name: [u8; 256],
    pub nl: usize,
    pub qtype: u16,
    pub qend: usize, // end of the question inside the DNS message
    pub edns: bool,
}

pub fn parse_query(dns: &[u8]) -> Option<Q> {
    if dns.len() < 12 + 5 || dns[2] & 0xf8 != 0 || u16::from_be_bytes([dns[4], dns[5]]) != 1 {
        return None; // not a standard query with one question
    }
    let mut name = [0u8; 256];
    let (nl, o) = read_name(dns, 12, &mut name, false)?;
    let qend = o + 4;
    if qend > dns.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([dns[o], dns[o + 1]]);
    // EDNS: ARCOUNT ≥ 1 and the first additional RR is a root-named OPT (type 41)
    let edns = u16::from_be_bytes([dns[10], dns[11]]) >= 1 && dns.get(qend) == Some(&0) && dns.get(qend + 1..qend + 3) == Some(&[0, 41]);
    Some(Q { name, nl, qtype, qend, edns })
}
