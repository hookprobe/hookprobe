#![no_main]
// Control-channel replies from the Wi-Fi firmware (ADR 0065 step 4d, `hal::bcdc::reply`): classifying any frame never
// panics, and a matched reply's body range lies inside the frame and the buffer.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let chan = data[2] & 0xf;
    let doff = data[3] as usize;
    let reqid = u16::from_le_bytes([data[4], data[5]]);
    let frame = &data[6..];
    if let hal::bcdc::Reply::Ours { off, end, .. } = hal::bcdc::reply(frame, len, chan, doff, reqid) {
        assert!(off <= end && end <= frame.len() && end <= len);
        assert!(off >= hal::SDPCM_HDRLEN + hal::bcdc::HDRLEN);
    }
});
