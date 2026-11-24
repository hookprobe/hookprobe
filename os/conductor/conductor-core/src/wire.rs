// SPDX-License-Identifier: AGPL-3.0-only
//! Bounds-checked little-endian reader and writer. Every read returns `None` past the end; nothing panics.

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    pub fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Some(a)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.arr::<1>()?[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.arr()?))
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.arr()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.arr()?))
    }
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    /// True when every byte was consumed (formats are exact-length: trailing bytes are an error).
    pub fn done(&self) -> bool {
        self.remaining() == 0
    }
}

pub struct Writer<'a> {
    b: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(b: &'a mut [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub fn put(&mut self, s: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(s.len())?;
        self.b.get_mut(self.pos..end)?.copy_from_slice(s);
        self.pos = end;
        Some(())
    }
    pub fn u8(&mut self, v: u8) -> Option<()> {
        self.put(&[v])
    }
    pub fn u16(&mut self, v: u16) -> Option<()> {
        self.put(&v.to_le_bytes())
    }
    pub fn u32(&mut self, v: u32) -> Option<()> {
        self.put(&v.to_le_bytes())
    }
    pub fn u64(&mut self, v: u64) -> Option<()> {
        self.put(&v.to_le_bytes())
    }
    pub fn len(&self) -> usize {
        self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
}
