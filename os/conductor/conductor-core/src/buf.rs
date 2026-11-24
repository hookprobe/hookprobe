// SPDX-License-Identifier: AGPL-3.0-only
//! A fixed-capacity byte buffer. Appends that do not fit fail and leave the buffer unchanged.

#[derive(Clone, Copy)]
pub struct Buf<const N: usize> {
    b: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Buf<N> {
    fn default() -> Self {
        Self { b: [0; N], len: 0 }
    }
}

impl<const N: usize> Buf<N> {
    pub const fn new() -> Self {
        Self { b: [0; N], len: 0 }
    }
    pub fn clear(&mut self) {
        self.b.fill(0);
        self.len = 0;
    }
    /// Let `f` write into the whole backing array and report the length it wrote (no stack temporary).
    pub fn fill_with(&mut self, f: impl FnOnce(&mut [u8]) -> Option<usize>) -> Option<()> {
        self.b.fill(0);
        self.len = 0;
        let n = f(&mut self.b)?;
        if n > N {
            return None;
        }
        self.len = n;
        Some(())
    }
    pub fn as_slice(&self) -> &[u8] {
        self.b.get(..self.len).unwrap_or(&[])
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Append all of `s`, or nothing.
    pub fn push(&mut self, s: &[u8]) -> Option<()> {
        let end = self.len.checked_add(s.len())?;
        self.b.get_mut(self.len..end)?.copy_from_slice(s);
        self.len = end;
        Some(())
    }
    pub fn set(&mut self, s: &[u8]) -> Option<()> {
        self.clear();
        self.push(s)
    }
    /// Append a decimal number.
    pub fn push_dec(&mut self, mut v: u64) -> Option<()> {
        let mut d = [0u8; 20];
        let mut i = d.len();
        loop {
            i = i.checked_sub(1)?;
            *d.get_mut(i)? = b'0'.checked_add(u8::try_from(v % 10).ok()?)?;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(d.get(i..)?)
    }
    /// Append lowercase hex.
    pub fn push_hex(&mut self, s: &[u8]) -> Option<()> {
        const H: &[u8; 16] = b"0123456789abcdef";
        for &x in s {
            self.push(&[*H.get(usize::from(x >> 4))?, *H.get(usize::from(x & 15))?])?;
        }
        Some(())
    }
}
