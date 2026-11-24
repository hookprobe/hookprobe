// SPDX-License-Identifier: AGPL-3.0-only
//! Byte-level BPE tokenizer, no allocation.
//!
//! Tokens 0..256 are the bytes. Merge `i` (rank i) turns the adjacent pair `merges[i]` into token 256 + i.
//! Encoding repeatedly applies the lowest-rank merge present anywhere in the sequence (the standard BPE
//! rule), finding a pair's rank by binary search in an index built offline. Decoding expands tokens with an
//! explicit stack. Any byte string encodes (there is no unknown token), and decode(encode(x)) == x.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpeError {
    /// The merge table or its index is inconsistent (checked by [`Bpe::new`]).
    Table,
    /// The output buffer is too small.
    Space,
    /// A token id outside the vocabulary.
    Token,
}

#[derive(Clone, Copy, Debug)]
pub struct Bpe<'a> {
    merges: &'a [(u16, u16)],
    /// (left, right, rank) sorted by (left, right): rank lookup in O(log m).
    index: &'a [(u16, u16, u16)],
}

impl<'a> Bpe<'a> {
    /// Check the tables once: each merge names only earlier tokens, the index is sorted, unique, and maps
    /// exactly the merges to their ranks.
    pub fn new(merges: &'a [(u16, u16)], index: &'a [(u16, u16, u16)]) -> Result<Self, BpeError> {
        if merges.len() > usize::from(u16::MAX) - 256 || index.len() != merges.len() {
            return Err(BpeError::Table);
        }
        for (i, &(a, b)) in merges.iter().enumerate() {
            let limit = 256 + i;
            if usize::from(a) >= limit || usize::from(b) >= limit {
                return Err(BpeError::Table);
            }
        }
        for w in index.windows(2) {
            if let [x, y] = w {
                if (x.0, x.1) >= (y.0, y.1) {
                    return Err(BpeError::Table);
                }
            }
        }
        for &(a, b, r) in index {
            if merges.get(usize::from(r)) != Some(&(a, b)) {
                return Err(BpeError::Table);
            }
        }
        Ok(Self { merges, index })
    }

    pub fn vocab(&self) -> usize {
        256 + self.merges.len()
    }

    fn rank(&self, a: u16, b: u16) -> Option<u16> {
        self.index.binary_search_by(|e| (e.0, e.1).cmp(&(a, b))).ok().and_then(|i| self.index.get(i)).map(|e| e.2)
    }

    /// Encode `text` into `out`. Returns the number of tokens.
    pub fn encode(&self, text: &[u8], out: &mut [u16]) -> Result<usize, BpeError> {
        let mut n = text.len();
        let buf = out.get_mut(..n).ok_or(BpeError::Space)?;
        for (o, &b) in buf.iter_mut().zip(text) {
            *o = u16::from(b);
        }
        loop {
            // Lowest-rank pair present (leftmost on ties).
            let mut best: Option<(u16, usize)> = None;
            for i in 0..n.saturating_sub(1) {
                if let (Some(&a), Some(&b)) = (out.get(i), out.get(i + 1)) {
                    if let Some(r) = self.rank(a, b) {
                        if best.is_none_or(|(br, _)| r < br) {
                            best = Some((r, i));
                        }
                    }
                }
            }
            let Some((r, _)) = best else { return Ok(n) };
            let pair = *self.merges.get(usize::from(r)).ok_or(BpeError::Table)?;
            let new = u16::try_from(256 + usize::from(r)).map_err(|_| BpeError::Table)?;
            // Apply this merge left to right across the whole sequence, compacting in place.
            let (mut rd, mut wr) = (0usize, 0usize);
            while rd < n {
                let a = out.get(rd).copied().ok_or(BpeError::Space)?;
                let b = out.get(rd + 1).copied();
                let tok = if rd + 1 < n && (Some(a), b) == (Some(pair.0), Some(pair.1)) {
                    rd += 2;
                    new
                } else {
                    rd += 1;
                    a
                };
                if let Some(o) = out.get_mut(wr) {
                    *o = tok;
                }
                wr += 1;
            }
            n = wr;
        }
    }

    /// Decode `ids` into bytes. Returns the number of bytes.
    pub fn decode(&self, ids: &[u16], out: &mut [u8]) -> Result<usize, BpeError> {
        let mut n = 0usize;
        // Depth is bounded by the merge chain length; 4,096 levels is far beyond any real vocabulary.
        let mut stack = [0u16; 4096];
        for &id in ids {
            if usize::from(id) >= self.vocab() {
                return Err(BpeError::Token);
            }
            let mut sp = 1usize;
            stack[0] = id;
            while sp > 0 {
                sp -= 1;
                let t = stack.get(sp).copied().ok_or(BpeError::Table)?;
                if t < 256 {
                    *out.get_mut(n).ok_or(BpeError::Space)? = t as u8;
                    n += 1;
                } else {
                    let (a, b) = *self.merges.get(usize::from(t) - 256).ok_or(BpeError::Token)?;
                    // Push right first so the left part is emitted first.
                    *stack.get_mut(sp).ok_or(BpeError::Table)? = b;
                    *stack.get_mut(sp + 1).ok_or(BpeError::Table)? = a;
                    sp += 2;
                }
            }
        }
        Ok(n)
    }
}
