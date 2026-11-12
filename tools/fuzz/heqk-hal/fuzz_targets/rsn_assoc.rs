#![no_main]
// WPA3 PMKSA caching: the station's (Re)Association Request elements (the CYW43455 ASSOC_IND / REASSOC_IND event
// data) are attacker-shaped. The RSNE walk never panics; a parsed RSNE keeps at most PMKIDS PMKIDs, each of them
// inside the input; the keying decision is total and never keys an AKM-8 station as PSK.
use hal::rsnassoc as r;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|d: &[u8]| {
    if d.is_empty() {
        return;
    }
    let (sel, ies) = (d[0], &d[1..]);
    let offers = (sel >> 2) & (r::OFFER_PSK | r::OFFER_SAE); // the BSS's current security (#1076)
    if let Some(b) = r::find_rsne(ies) {
        assert!(b.len() <= 255);
    }
    let a = r::assoc_rsn(ies);
    if let Some(x) = a {
        assert!(x.pmkids().len() <= r::PMKIDS && x.pmkids().len() <= x.n_pmkid as usize);
        for p in x.pmkids() {
            assert!(ies.windows(16).any(|w| w == p));
        }
        let k = r::decide(Some(&x), offers, sel & 1 != 0, &mut |p| (p[0] & 1 != 0) == (sel & 2 != 0));
        if x.akm == r::AKM_SAE && x.n_akm == 1 {
            assert!(k != r::Keying::Psk && k != r::Keying::Legacy);
            if offers & r::OFFER_SAE == 0 {
                assert_eq!(k, r::Keying::NotOffered); // never key SAE on a BSS that does not offer it
            }
        }
        if let r::Keying::SaeCached(i) = k {
            assert!(i < x.pmkids().len());
        }
    }
    assert_eq!(r::decide(None, offers, sel & 1 != 0, &mut |_| true), r::Keying::Legacy);
});
