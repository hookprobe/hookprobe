#![no_main]
// ADR 0065 step 3a: the authenticator state machine fed arbitrary "M2 / M4" frames and clock ticks. It must never
// panic, never key a station without a frame whose MIC verifies under the real PTK (random bytes cannot), and it
// must always end (give up) after MAX_SENDS resends.
use hal::wpakeyer::*;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut k = Keyer::new();
    let mut out = [0u8; FRAME_MAX];
    let sta = [2, 0x5a, 0, 0, 0, 9];
    let st = Start {
        sta,
        aa: [2, 0xaa, 0, 0, 0, 1],
        pmk: [0x11; 32],
        akm8: data.first().is_some_and(|b| b & 1 == 1),
        pmkid: None,
        anonce: [0x22; 32],
        kd: KeyData { rsne: [0; 40], rsne_len: 0, gtk: [0x33; 16], gtk_keyid: 1, igtk_kde: Some([0x44; 30]) },
    };
    let _ = k.start(st, 0, &mut out);
    let mut t = 0u64;
    for chunk in data.chunks(128) {
        match k.on_eapol(&sta, chunk, t, &mut Direct, &mut out) {
            Out::Keyed { .. } => panic!("keyed on random bytes"),
            Out::Send(n) => assert!(n <= FRAME_MAX),
            _ => {}
        }
        t += 700;
        let _ = k.tick(t, &mut out);
    }
    for _ in 0..(MAX_SENDS as u64 + 2) {
        t += RESEND_MS;
        let _ = k.tick(t, &mut out);
    }
    assert_eq!(k.pending(), 0, "every handshake ends");
});
