#![no_main]
// The el0-wifi frame-command messages (ADR 0065 steps 4b-2b / 4c / 4d). The server's replies are untrusted: decoding
// any bytes never panics; an accepted frame reply carries a header the kernel's own check accepts, with exactly the
// claimed length, and the rest of the kernel's buffer is zero. The request decoders (the server's side) never panic.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut rx = [0xa5u8; 2048];
    if let Some((r, _)) = hal::wifisrvabi::rxmsg::decode_out(data, &mut rx) {
        if let hal::sdio::RxRead::Frame { hdr, len, .. } = r {
            assert_eq!(hal::sdpcm_hdr(&rx[..hal::sdio::FIRSTREAD]), Ok(Some(hdr)));
            assert_eq!(hdr.len, len);
            let nb = (len as usize).max(hal::sdio::FIRSTREAD);
            assert!(rx[nb..].iter().all(|&b| b == 0));
        }
    }
    let _ = hal::wifisrvabi::rxmsg::decode_in(data);
    let _ = hal::wifisrvabi::txmsg::decode_in(data);
    if data.len() >= 4 {
        let _ = hal::wifisrvabi::txmsg::decode_r0(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
    }
    let _ = hal::wifisrvabi::ctlmsg::decode_in(data);
});
