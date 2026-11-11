//! ADR 0050 D4 step 5b: the WPA authenticator's work on what a station sends — the PTK derivation over the station's
//! SNonce and the EAPOL-Key MIC checks of M2 / M4 — pure and allocation-free, run in `el0-lansvc`. The kernel keeps
//! the state machine, the replay counters, M1 / M3 building and the key installation.
//!
//! Frames are the 802.1X frame (from the version byte): key body at 4, SNonce at 4+13..4+45, MIC at 4+77..4+93.

const BODY: usize = 4;
const MIC_AT: usize = BODY + 77;
/// Largest EAPOL-Key frame verified (the driver's M2 / M4 buffers are 512 B).
pub const FRAME_MAX: usize = 512;

/// IEEE 802.11 KDF-SHA256 for the 384-bit PTK (hostapd `sha256_prf_bits`, AKM 8): HMAC(PMK, i ‖ label ‖ ctx ‖ L).
fn kdf_sha256_ptk(pmk: &[u8; 32], ctx: &[u8; 76]) -> [u8; 48] {
    const LABEL: &[u8] = b"Pairwise key expansion";
    let mut out = [0u8; 48];
    let mut m = [0u8; 2 + 22 + 76 + 2];
    m[24..100].copy_from_slice(ctx);
    m[2..24].copy_from_slice(LABEL);
    m[100..102].copy_from_slice(&384u16.to_le_bytes());
    for (k, chunk) in out.chunks_mut(32).enumerate() {
        m[0..2].copy_from_slice(&((k + 1) as u16).to_le_bytes());
        let h = boot_abi::kdf::hmac_sha256(pmk, &m);
        chunk.copy_from_slice(&h[..chunk.len()]);
    }
    out
}

/// The PTK (KCK ‖ KEK ‖ TK, 48 B): PRF-SHA1 for AKM 2 (PSK), KDF-SHA256 for AKM 8 (SAE).
pub fn ptk(akm8: bool, pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> [u8; 48] {
    if !akm8 {
        return crate::wpa::wpa_ptk(pmk, aa, spa, anonce, snonce);
    }
    let (a1, a2) = if aa < spa { (aa, spa) } else { (spa, aa) };
    let (n1, n2) = if anonce < snonce { (anonce, snonce) } else { (snonce, anonce) };
    let mut ctx = [0u8; 76];
    ctx[0..6].copy_from_slice(a1);
    ctx[6..12].copy_from_slice(a2);
    ctx[12..44].copy_from_slice(n1);
    ctx[44..76].copy_from_slice(n2);
    kdf_sha256_ptk(pmk, &ctx)
}

/// The EAPOL-Key MIC: HMAC-SHA1-128 (key-descriptor v2, AKM 2) or AES-128-CMAC (AKM 8).
pub fn mic(kck: &[u8; 16], eapol: &[u8], akm8: bool) -> [u8; 16] {
    if akm8 { crate::aes::aes_cmac(kck, eapol) } else { crate::wpa::wpa_mic_sha1(kck, eapol) }
}

/// Does the frame's MIC verify under `kck`? Recomputed over a private copy with the MIC field zeroed; a frame too
/// short to hold a MIC, or longer than FRAME_MAX, does not verify.
pub fn mic_ok(kck: &[u8; 16], frame: &[u8], akm8: bool) -> bool {
    if frame.len() < MIC_AT + 16 || frame.len() > FRAME_MAX {
        return false;
    }
    let mut c = [0u8; FRAME_MAX];
    let f = &mut c[..frame.len()];
    f.copy_from_slice(frame);
    let mut want = [0u8; 16];
    want.copy_from_slice(&f[MIC_AT..MIC_AT + 16]);
    f[MIC_AT..MIC_AT + 16].fill(0);
    let got = mic(kck, f, akm8);
    // constant-time compare
    got.iter().zip(want.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

/// M2: derive the PTK from the station's SNonce and verify M2's MIC with its KCK. Some(PTK) only when it verifies.
pub fn on_m2(pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], akm8: bool, m2: &[u8]) -> Option<[u8; 48]> {
    if m2.len() < MIC_AT + 16 || m2.len() > FRAME_MAX {
        return None;
    }
    let mut snonce = [0u8; 32];
    snonce.copy_from_slice(&m2[BODY + 13..BODY + 45]);
    let p = ptk(akm8, pmk, aa, spa, anonce, &snonce);
    let mut kck = [0u8; 16];
    kck.copy_from_slice(&p[..16]);
    mic_ok(&kck, m2, akm8).then_some(p)
}

/// M4: verify the MIC with the session's KCK.
pub fn on_m4(kck: &[u8; 16], akm8: bool, m4: &[u8]) -> bool {
    mic_ok(kck, m4, akm8)
}

/// Wipe key material so the compiler cannot elide it (operator 2026-11-11: the PMK is erased when no longer needed).
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ---- the EL0 records (fixed layout, decoded and clamped by the kernel) ----
/// M2 IN prefix: pmk 32 ‖ aa 6 ‖ spa 6 ‖ anonce 32 ‖ akm8 u8, then the 802.1X frame.
pub const M2_PRE: usize = 32 + 6 + 6 + 32 + 1;
/// M2 OUT: ok u8 ‖ ptk 48.
pub const M2_OUT: usize = 1 + 48;
/// M4 IN prefix: kck 16 ‖ akm8 u8, then the frame. OUT: ok u8.
pub const M4_PRE: usize = 16 + 1;
