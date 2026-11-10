#![no_main]
// ADR 0050 D4 step 2b: the DHCP server's client-frame parse (runs in el0-lansvc) — every byte attacker-chosen —
// plus the kernel's decode of the EL0 record (a compromised server must never overrun the kernel).
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let r = hal::dhcpwire::parse_client(data);
    let mut rec = [0u8; hal::dhcpwire::REC_LEN];
    hal::dhcpwire::encode(&r, &mut rec);
    let back = hal::dhcpwire::decode(&rec);
    assert!(back.mt == r.mt && back.cmac == r.cmac && back.id.hlen == r.id.hlen && back.id.plen == r.id.plen);
    if data.len() >= hal::dhcpwire::REC_LEN {
        let d = hal::dhcpwire::decode(data[..hal::dhcpwire::REC_LEN].try_into().unwrap());
        assert!(d.id.hlen <= 32 && d.id.vlen <= 32 && d.id.plen <= 24);
    }
});
