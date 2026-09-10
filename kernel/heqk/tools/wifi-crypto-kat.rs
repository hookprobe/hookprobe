//! P-wifi-crypto — offline KAT harness for the cm5-gated WiFi/WPA crypto
//! (`arch-aarch64/src/aes.rs` + `arch-aarch64/src/wpa.rs`). Those modules are
//! `#[cfg(feature = "cm5")]` in `arch-aarch64/src/lib.rs`, so they compile ONLY in
//! the metal flavour and are ABSENT from the qemu-virt `kernel` that `validate.sh`
//! boots — leaving the AES key-wrap (WPA2 GTK), PBKDF2-HMAC-SHA1 PMK, PRF-384 PTK
//! and HMAC-SHA1-128 EAPOL MIC with no automated coverage, and their in-tree KATs
//! (`aes_selftest`, `wpa_pmk_selftest`) as dead code with no callers. This host
//! harness (std, `rustc` — driven by validate.sh Stage-1c) runs those KATs against
//! the SAME source the kernel uses (`#[path]`, no drift) plus wrap/unwrap-tamper
//! and PTK/MIC self-consistency vectors. The P16 short-tail-HMAC bug is the
//! standing proof that crypto QEMU<->metal gaps bite.

#[path = "../arch-aarch64/src/aes.rs"]
mod aes;
#[path = "../arch-aarch64/src/wpa.rs"]
mod wpa;

fn check(name: &str, pass: bool, ok: &mut bool) {
    println!("  {:<48} {}", name, if pass { "PASS" } else { "FAIL" });
    if !pass {
        *ok = false;
    }
}

fn main() {
    let mut ok = true;

    // 1. AES-128 (FIPS-197) + RFC 3394 wrap/unwrap round-trip (the in-tree KAT).
    check("aes_selftest (FIPS-197 + RFC3394)", aes::aes_selftest(), &mut ok);

    // 1b. Explicit RFC-3394 wrap -> unwrap round-trip + integrity tamper-reject.
    {
        let kek = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mut wrapped = [0u8; 24];
        let mut back = [0u8; 16];
        let w = aes::aes_wrap(&kek, &pt, &mut wrapped);
        let u = if w == Some(24) { aes::aes_unwrap(&kek, &wrapped, &mut back) } else { None };
        check("aes_wrap -> aes_unwrap round-trip", u == Some(16) && back == pt, &mut ok);
        wrapped[10] ^= 0x01; // corrupt one wrapped byte
        check(
            "aes_unwrap tamper-reject (RFC3394 IV)",
            aes::aes_unwrap(&kek, &wrapped, &mut back).is_none(),
            &mut ok,
        );
    }

    // 2. PBKDF2-HMAC-SHA1 PMK KAT (IEEE 802.11i "password"/"IEEE").
    check("wpa_pmk_selftest (PBKDF2-HMAC-SHA1)", wpa::wpa_pmk_selftest(), &mut ok);

    // 3. PRF-384 PTK determinism + role symmetry, HMAC-SHA1-128 MIC self-consistency.
    {
        let pmk = wpa::wpa_pmk(b"password", b"IEEE");
        let aa = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        let spa = [0x66u8, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];
        let ptk1 = wpa::wpa_ptk(&pmk, &aa, &spa, &anonce, &snonce);
        let ptk2 = wpa::wpa_ptk(&pmk, &aa, &spa, &anonce, &snonce);
        // wpa_ptk sorts (AA,SPA) and (ANonce,SNonce) by min/max, so swapping BOTH pairs
        // (authenticator vs supplicant viewpoint) must yield the identical PTK.
        let ptk3 = wpa::wpa_ptk(&pmk, &spa, &aa, &snonce, &anonce);
        check("wpa_ptk PRF-384 deterministic", ptk1 == ptk2, &mut ok);
        check("wpa_ptk role-symmetric (min/max)", ptk1 == ptk3, &mut ok);

        let mut kck = [0u8; 16];
        kck.copy_from_slice(&ptk1[0..16]);
        let eapol = [
            0x01u8, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        ];
        let mic1 = wpa::wpa_mic_sha1(&kck, &eapol);
        let mic2 = wpa::wpa_mic_sha1(&kck, &eapol);
        let mut eapol_t = eapol;
        eapol_t[4] ^= 0x01; // flip one frame byte
        let mic_t = wpa::wpa_mic_sha1(&kck, &eapol_t);
        check("wpa_mic_sha1 deterministic", mic1 == mic2, &mut ok);
        check("wpa_mic_sha1 avalanche (frame-sensitive)", mic1 != mic_t, &mut ok);
    }

    if ok {
        println!("[P-wifi-crypto] PASS");
    } else {
        println!("[P-wifi-crypto] FAIL");
        std::process::exit(1);
    }
}
