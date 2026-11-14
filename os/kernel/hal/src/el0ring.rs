//! ADR 0065 step 2: the frame ring between the kernel and a resident EL0 driver server.
//!
//! One page of header (`head` u32 at 0, `tail` u32 at 4) then `SLOTS` fixed slots of `SLOT_BYTES`
//! (`len` u16 at 0, the frame at 4..). The producer writes slot `head % SLOTS` then advances `head`; the consumer
//! reads slot `tail % SLOTS` then advances `tail`. Calls are synchronous (EL0 excursions), so the two sides never
//! run at the same time.
//!
//! Every value written by the OTHER side is untrusted: the consumer re-checks the fill (`head - tail <= SLOTS`) and
//! each length (`<= FRAME_MAX` and the caller's buffer) and never reads outside a slot; a bad ring is resynced
//! (`tail = head`, counted) rather than trusted. The memory is reached through [`RingMem`] so the kernel can use it
//! over scattered physical frames and the server over its contiguous mapping. Pure; host-tested; fuzzed (`el0_ring`).

/// Slots per ring.
pub const SLOTS: usize = 32;
/// Bytes per slot (length word + frame).
pub const SLOT_BYTES: usize = 2048;
/// Header size (one page; only the first 8 bytes are used).
pub const HDR: usize = 0x1000;
/// The largest frame a slot carries.
pub const FRAME_MAX: usize = SLOT_BYTES - 4;
/// Bytes one ring occupies.
pub const RING_BYTES: usize = HDR + SLOTS * SLOT_BYTES;

/// Byte access to a ring's memory (offsets are within `0..RING_BYTES`).
pub trait RingMem {
    fn read(&self, off: usize, out: &mut [u8]);
    fn write(&mut self, off: usize, data: &[u8]);
}

/// A contiguous ring (the server's view; tests).
impl RingMem for [u8] {
    fn read(&self, off: usize, out: &mut [u8]) {
        let n = out.len();
        out.copy_from_slice(&self[off..off + n]);
    }
    fn write(&mut self, off: usize, data: &[u8]) {
        self[off..off + data.len()].copy_from_slice(data);
    }
}

fn rd32<M: RingMem + ?Sized>(m: &M, off: usize) -> u32 {
    let mut b = [0u8; 4];
    m.read(off, &mut b);
    u32::from_le_bytes(b)
}
fn wr32<M: RingMem + ?Sized>(m: &mut M, off: usize, v: u32) {
    m.write(off, &v.to_le_bytes());
}

/// What one `pop` found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pop {
    Empty,
    /// A frame of this many bytes is in the caller's buffer.
    Frame(usize),
    /// The other side left the ring inconsistent (fill > SLOTS, or a length out of bounds): the ring was resynced
    /// (`tail = head`) and nothing was read.
    Bad,
}

/// Zero a ring (both indices and every slot's length word).
pub fn reset<M: RingMem + ?Sized>(m: &mut M) {
    wr32(m, 0, 0);
    wr32(m, 4, 0);
    for s in 0..SLOTS {
        m.write(HDR + s * SLOT_BYTES, &[0, 0]);
    }
}

/// Frames waiting (0 when the indices are inconsistent; `pop` reports that as `Bad`).
pub fn pending<M: RingMem + ?Sized>(m: &M) -> usize {
    let fill = rd32(m, 0).wrapping_sub(rd32(m, 4)) as usize;
    if fill > SLOTS { 0 } else { fill }
}

/// Producer: append one frame. False when the ring is full, the frame is too big, or the indices are inconsistent
/// (the producer never writes over a slot the consumer may still own).
pub fn push<M: RingMem + ?Sized>(m: &mut M, frame: &[u8]) -> bool {
    let (head, tail) = (rd32(m, 0), rd32(m, 4));
    let fill = head.wrapping_sub(tail) as usize;
    if frame.len() > FRAME_MAX || fill >= SLOTS {
        return false;
    }
    let slot = HDR + (head as usize % SLOTS) * SLOT_BYTES;
    m.write(slot, &(frame.len() as u16).to_le_bytes());
    m.write(slot + 4, frame);
    wr32(m, 0, head.wrapping_add(1));
    true
}

/// Consumer: take one frame into `out`.
pub fn pop<M: RingMem + ?Sized>(m: &mut M, out: &mut [u8]) -> Pop {
    let (head, tail) = (rd32(m, 0), rd32(m, 4));
    let fill = head.wrapping_sub(tail) as usize;
    if fill == 0 {
        return Pop::Empty;
    }
    if fill > SLOTS {
        wr32(m, 4, head);
        return Pop::Bad;
    }
    let slot = HDR + (tail as usize % SLOTS) * SLOT_BYTES;
    let mut l = [0u8; 2];
    m.read(slot, &mut l);
    let len = u16::from_le_bytes(l) as usize;
    if len > FRAME_MAX || len > out.len() {
        wr32(m, 4, head);
        return Pop::Bad;
    }
    m.read(slot + 4, &mut out[..len]);
    wr32(m, 4, tail.wrapping_add(1));
    Pop::Frame(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn frames_go_through_in_order_and_the_ring_wraps() {
        let mut r = vec![0u8; RING_BYTES];
        reset(&mut r[..]);
        let mut out = [0u8; FRAME_MAX];
        for round in 0..3u8 {
            for i in 0..SLOTS as u8 {
                assert!(push(&mut r[..], &[round, i, 7]));
            }
            assert!(!push(&mut r[..], &[0]), "full");
            assert_eq!(pending(&r[..]), SLOTS);
            for i in 0..SLOTS as u8 {
                assert_eq!(pop(&mut r[..], &mut out), Pop::Frame(3));
                assert_eq!(&out[..3], &[round, i, 7]);
            }
            assert_eq!(pop(&mut r[..], &mut out), Pop::Empty);
        }
    }
    #[test]
    fn a_full_size_frame_fits_one_byte_more_does_not() {
        let mut r = vec![0u8; RING_BYTES];
        assert!(push(&mut r[..], &[1u8; FRAME_MAX]));
        assert!(!push(&mut r[..], &[1u8; FRAME_MAX + 1]));
        let mut out = [0u8; FRAME_MAX];
        assert_eq!(pop(&mut r[..], &mut out), Pop::Frame(FRAME_MAX));
    }
    #[test]
    fn a_hostile_producer_cannot_make_the_consumer_over_read() {
        let mut r = vec![0u8; RING_BYTES];
        let mut out = [0u8; 1600];
        // a length past the slot
        assert!(push(&mut r[..], &[1, 2, 3]));
        r[HDR..HDR + 2].copy_from_slice(&0xffffu16.to_le_bytes());
        assert_eq!(pop(&mut r[..], &mut out), Pop::Bad);
        assert_eq!(pop(&mut r[..], &mut out), Pop::Empty, "resynced");
        // a length larger than the consumer's buffer
        assert!(push(&mut r[..], &[9u8; 2000]));
        assert_eq!(pop(&mut r[..], &mut out), Pop::Bad);
        // a head far ahead of the tail
        r[0..4].copy_from_slice(&1000u32.to_le_bytes());
        assert_eq!(pending(&r[..]), 0);
        assert_eq!(pop(&mut r[..], &mut out), Pop::Bad);
        assert_eq!(pop(&mut r[..], &mut out), Pop::Empty);
    }
    #[test]
    fn a_hostile_consumer_cannot_make_the_producer_overwrite() {
        let mut r = vec![0u8; RING_BYTES];
        // tail moved ahead of head by the other side: fill looks huge, push refuses
        r[4..8].copy_from_slice(&5u32.to_le_bytes());
        assert!(!push(&mut r[..], &[1]));
        reset(&mut r[..]);
        assert!(push(&mut r[..], &[1]));
    }
}
