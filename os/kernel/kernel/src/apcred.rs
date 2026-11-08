//! Setup-AP credential (parity G12, ADR 0054): a per-device Wi-Fi SSID + WPA2 passphrase.
//!
//! Derived from the device sealing root (SRK, which HBoot derives from the per-device OTP secret
//! and EL1 cannot read back): `HKDF(SRK, "HQ-AP-SETUP")`. So every device has its own credential,
//! there is no universal default, and a reset re-derives the SAME device-unique value — never a
//! shared password. The value is meant for the end-of-line label / QR code.
//!
//! Precedence (main.rs): operator-signed WIFI.TXT (the client AP) > bench build env > this setup
//! credential > no AP at all. Without a real SRK (QEMU, no OTP secret) this returns None: the
//! synthetic fallback key is the same on every device and must never become a Wi-Fi password.

/// Unambiguous lowercase alphabet (Crockford base32: no i, l, o, u) — easy to read off a label.
const ALPHA: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Passphrase: 4 groups of 4 characters joined by '-' = 19 bytes, 80 bits of key material.
pub const PSK_LEN: usize = 19;
/// SSID: "HookProbe-Setup-" + 4 characters.
pub const SSID_LEN: usize = 20;

pub struct Cred {
    pub ssid: [u8; SSID_LEN],
    pub psk: [u8; PSK_LEN],
}

impl Cred {
    pub fn ssid_str(&self) -> &str {
        core::str::from_utf8(&self.ssid).unwrap_or("?")
    }
    pub fn psk_str(&self) -> &str {
        core::str::from_utf8(&self.psk).unwrap_or("?")
    }
}

/// Keys that are the same on every device (fallbacks) — never usable for a credential.
fn is_shared_key(srk: &[u8; 32]) -> bool {
    srk.iter().all(|&b| b == srk[0]) // all-zero, the 0x5a synthetic key, any constant fill
}

/// Derive the setup credential, or None when the key is not device-unique.
pub fn derive(srk: &[u8; 32]) -> Option<Cred> {
    if is_shared_key(srk) {
        return None;
    }
    let prk = boot_abi::kdf::hkdf_extract(b"HQ-AP-SETUP", srk);
    let k_psk = boot_abi::kdf::hkdf_expand32(&prk, b"psk v1");
    let k_id = boot_abi::kdf::hkdf_expand32(&prk, b"ssid v1");
    let mut c = Cred { ssid: *b"HookProbe-Setup-0000", psk: [b'-'; PSK_LEN] };
    // 16 characters x 5 bits = 80 bits, one byte per character (low 5 bits).
    for i in 0..16 {
        c.psk[i + i / 4] = ALPHA[(k_psk[i] & 31) as usize];
    }
    for i in 0..4 {
        c.ssid[16 + i] = ALPHA[(k_id[i] & 31) as usize].to_ascii_uppercase();
    }
    Some(c)
}

/// The standard Wi-Fi QR payload (`WIFI:T:WPA;S:...;P:...;;`) for the label / Mission Control.
/// Our SSID and passphrase alphabets need no escaping.
pub fn qr_payload<'a>(c: &Cred, out: &'a mut [u8; 64]) -> &'a str {
    let mut n = 0;
    for part in [b"WIFI:T:WPA;S:".as_slice(), &c.ssid, b";P:", &c.psk, b";;"] {
        out[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// `[P-apcred]`: deterministic per key, distinct across keys, valid WPA2 passphrase, shared
/// fallback keys refused, QR payload well formed.
pub fn selftest() -> bool {
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    for i in 0..32 {
        k1[i] = i as u8 ^ 0xA7;
        k2[i] = i as u8 ^ 0x3C;
    }
    let (a, a2, b) = (derive(&k1), derive(&k1), derive(&k2));
    let stable = matches!((&a, &a2), (Some(x), Some(y)) if x.psk == y.psk && x.ssid == y.ssid);
    let distinct = matches!((&a, &b), (Some(x), Some(y)) if x.psk != y.psk);
    let valid = a.as_ref().is_some_and(|c| {
        c.psk.len() >= 8 && c.psk.len() <= 63
            && c.psk.iter().enumerate().all(|(i, &ch)| if i % 5 == 4 { ch == b'-' } else { ALPHA.contains(&ch) })
            && c.ssid.starts_with(b"HookProbe-Setup-")
    });
    let shared_refused = derive(&[0x5a; 32]).is_none() && derive(&[0; 32]).is_none();
    let mut qb = [0u8; 64];
    let qr_ok = a.as_ref().is_some_and(|c| {
        let q = qr_payload(c, &mut qb);
        q.starts_with("WIFI:T:WPA;S:HookProbe-Setup-") && q.ends_with(";;") && q.contains(c.psk_str())
    });
    let pass = stable && distinct && valid && shared_refused && qr_ok;
    arch_aarch64::_print(format_args!(
        " [P-apcred] {} — G12 setup-AP credential: derived per device from the SRK (stable={} distinct across devices={} valid WPA2 passphrase, 80 bits={} shared/synthetic key refused={} QR payload={})\n",
        if pass { "PASS" } else { "FAIL" }, stable, distinct, valid, shared_refused, qr_ok
    ));
    pass
}
