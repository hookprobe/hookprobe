#![no_main]
// ADR 0050 D4 step 3b: the PPP control parsers that run in el0-lansvc (LCP ConfReq, IPCP Req/Nak/Rej, CHAP
// Challenge, IPv6CP ConfReq) on attacker bytes, plus the kernel-side decode of each EL0 record (lengths clamped).
use hal::pppwire as p;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let l = p::lcp_classify(data);
    assert!(p::decode_lcp(&p::encode_lcp(&l)) == l || l.auth != 0);
    for code in [1u8, 3, 4] {
        let f = p::ipcp_facts(code, data);
        assert!(p::decode_ipcp(&p::encode_ipcp(&f)) == f);
    }
    let c = p::chap_challenge(data);
    assert!(p::decode_chap(&p::encode_chap(&c)) == c);
    for code in [3u8, 4] {
        let f = p::lcp_peer(code, data);
        assert!(p::decode_lcp_peer(&p::encode_lcp_peer(&f)) == f);
    }
    let r = p::ip6cp_req(data);
    assert!(p::decode_ip6cp(&p::encode_ip6cp(&r)) == r);
    if data.len() >= p::LCP_LEN {
        let d = p::decode_lcp(data[..p::LCP_LEN].try_into().unwrap());
        assert!(d.nrej <= 128 && d.nnak <= 16);
    }
});
