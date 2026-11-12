//! WPA authenticator frame parsing (ADR 0050 D4 step 5a): what a station sends during the 4-way handshake — EAPOL-Key
//! frames (M2 / M4) and the RSNE inside M2's key data — attacker-shaped bytes from anyone in radio range. Pure,
//! allocation-free: compiled into the kernel (fallback) and into `el0-lansvc`. The authenticator keeps every decision
//! (MIC, keys, state); only the classification runs here.

/// Is Ethernet frame `e` an EAPOL-Key from `sta` with the pairwise / MIC / no-ACK bits, the expected Secure bit and
/// replay counter? Some(n) = the 802.1X length to take from `e[14..]` (4 + body length); None = not ours / stale.
pub fn eapol_key(e: &[u8], sta: &[u8; 6], secure: bool, replay: u64) -> Option<usize> {
    let body = 18usize;
    if body + 95 > e.len() {
        return None;
    }
    if u16::from_be_bytes([e[12], e[13]]) != 0x888E || e[6..12] != sta[..] {
        return None;
    }
    let ki = u16::from_be_bytes([e[body + 1], e[body + 2]]);
    let pairwise_mic_noack = ki & 0x0008 != 0 && ki & 0x0100 != 0 && ki & 0x0080 == 0;
    if !pairwise_mic_noack || (ki & 0x0200 != 0) != secure {
        return None;
    }
    let rc = u64::from_be_bytes(e[body + 5..body + 13].try_into().unwrap());
    if rc != replay {
        return None; // stale (previous session / previous retransmit)
    }
    let x1 = u16::from_be_bytes([e[16], e[17]]) as usize;
    let n = 4 + x1;
    if 14 + n > e.len() {
        return None;
    }
    Some(n)
}

/// Did the station's M2 RSNE (key data) advertise MFP-capable? `m2` = the 802.1X frame, `body_off` = its key body.
pub fn m2_mfpc(m2: &[u8], body_off: usize) -> bool {
    let kl_at = body_off + 93;
    if kl_at + 2 > m2.len() {
        return false;
    }
    let kl = u16::from_be_bytes([m2[kl_at], m2[kl_at + 1]]) as usize;
    let kd = &m2[(kl_at + 2).min(m2.len())..(kl_at + 2 + kl).min(m2.len())];
    let mut i = 0;
    while i + 2 <= kd.len() {
        let (id, l) = (kd[i], kd[i + 1] as usize);
        if id == 0x30 && i + 2 + l <= kd.len() {
            let e = &kd[i + 2..i + 2 + l];
            // version 2 | group 4 | pairwise count 2 + 4n | akm count 2 + 4m | caps 2
            if e.len() < 8 {
                return false;
            }
            let pc = u16::from_le_bytes([e[6], e[7]]) as usize;
            let a = 8 + 4 * pc;
            if a + 2 > e.len() {
                return false;
            }
            let ac = u16::from_le_bytes([e[a], e[a + 1]]) as usize;
            let c = a + 2 + 4 * ac;
            return c + 2 <= e.len() && e[c] & 0x80 != 0;
        }
        i += 2 + l;
    }
    false
}
