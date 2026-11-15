#![no_main]
// ADR 0065: a frame ring written by an untrusted EL0 driver. Whatever the bytes, the kernel-side consumer never
// reads outside the ring, never hands out a frame longer than FRAME_MAX or its buffer, and after a Bad the ring is
// resynced (empty). The producer side never claims a slot the consumer may own.
use hal::el0ring as r;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut ring = vec![0u8; r::RING_BYTES];
    let n = data.len().min(r::RING_BYTES);
    ring[..n].copy_from_slice(&data[..n]);
    let buflen = data.first().map_or(1600, |&b| 64 + (b as usize) * 8);
    let mut out = vec![0u8; buflen];
    for _ in 0..(r::SLOTS + 2) {
        match r::pop(&mut ring[..], &mut out) {
            r::Pop::Frame(k) => assert!(k <= r::FRAME_MAX && k <= buflen),
            r::Pop::Bad => {
                assert_eq!(r::pop(&mut ring[..], &mut out), r::Pop::Empty);
                break;
            }
            r::Pop::Empty => break,
        }
    }
    if r::push(&mut ring[..], &data[..data.len().min(r::FRAME_MAX)]) {
        assert!(r::pending(&ring[..]) >= 1);
    }
});
