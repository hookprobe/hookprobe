#![no_main]
// ADR 0059 D9: the fixed management-ABI records (the EL0 shell formats them; the kernel decodes requests). Every
// record decoder on arbitrary bytes, the Act reason text (UTF-8 from the record), and the per-message role / reply
// length tables: never panic, the reason stays inside its 56-byte field.
use hal::mgmtabi as m;
use libfuzzer_sys::fuzz_target;
fn arr<const N: usize>(d: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    let n = d.len().min(N);
    a[..n].copy_from_slice(&d[..n]);
    a
}
fuzz_target!(|d: &[u8]| {
    let _ = m::Info::decode(&arr(d));
    let _ = m::Wan::decode(&arr(d));
    let _ = m::Qs::decode(&arr(d));
    let _ = m::Cfg::decode(&arr(d));
    let _ = m::Anchor::decode(&arr(d));
    let _ = m::Parsers::decode(&arr(d));
    let _ = m::Challenge::decode(&arr(d));
    let a = m::Act::decode(&arr(d));
    assert!(a.reason_str().len() <= 56);
    if d.len() >= 2 {
        let msg = u16::from_le_bytes([d[0], d[1]]);
        let _ = (m::role_for(msg), m::reply_len(msg));
    }
});
