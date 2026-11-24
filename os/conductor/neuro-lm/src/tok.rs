// SPDX-License-Identifier: AGPL-3.0-only
//! The Qwen2/Qwen3 tokenizer: byte-level BPE with 32-bit ids, the Qwen2 pre-tokenizer, added tokens.
//! No allocation, no float, no Unicode library: everything comes from one table blob built on the build
//! host (`tok-build`) and validated by [`Tokenizer::new`].
//!
//! Encoding follows the model's `tokenizer.json` (HF `tokenizers`):
//! 1. added tokens (`<|im_start|>`, `<tool_call>`, …) are found first, leftmost-longest, on the raw text;
//! 2. the text between them is put in NFC (the model's normaliser): a quick check (UAX #15) passes almost
//!    all text through untouched; anything else is decomposed, canonically reordered and recomposed with
//!    tables from the blob (Hangul algorithmically) by [`Tokenizer::encode_nfc`]. [`Tokenizer::encode`]
//!    has no scratch memory and refuses such text with [`TokError::NotNfc`] instead;
//! 3. the Qwen2 pre-tokenizer splits it, by this pattern, implemented by hand (leftmost-first):
//!    `(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+`
//! 4. each piece's UTF-8 bytes start as byte tokens and the lowest-rank merge present is applied until
//!    none is (classic BPE; equal to HF's priority-queue order for trained merge lists).
//!
//! # Blob layout (all integers u32 little-endian)
//! ```text
//! "QTK2" n_vocab n_merges n_added n_ranges n_decomp n_dpool n_comp
//! byte_ids[256]                      token id of each single byte
//! merges[n_merges] (a, b, rank, new) sorted by (a, b), unique
//! offsets[n_vocab + 1]               token bytes are pool[offsets[i]..offsets[i+1]]
//! added[n_added]                     ids of added tokens (their text is their bytes)
//! ranges[n_ranges] (first, last, class) sorted, disjoint code-point ranges
//! decomp[n_decomp] (cp, start | len << 24) full canonical decompositions, sorted by cp (no Hangul)
//! dpool[n_dpool]                     their code points
//! comp[n_comp] (a, b, composite)     primary compositions, sorted by (a, b) (no Hangul)
//! pool                               token bytes, exactly offsets[n_vocab] long
//! ```
//! `class`: bit 0 letter (`\p{L}`), bit 1 number (`\p{N}`), bit 2 whitespace (`\s`), bit 3 NFC quick
//! check No, bit 4 NFC quick check Maybe, bits 8–15 canonical combining class.

pub const MAGIC: [u8; 4] = *b"QTK2";
pub const LETTER: u32 = 1;
pub const NUMBER: u32 = 2;
pub const SPACE: u32 = 4;
pub const NFC_NO: u32 = 8;
pub const NFC_MAYBE: u32 = 16;
/// Longest token, in bytes (a validation bound).
pub const MAX_TOKEN_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokError {
    /// The blob is malformed or inconsistent.
    Table,
    /// The text is not UTF-8.
    Utf8,
    /// The text is not in NFC (or the quick check cannot tell); the reference would normalise it.
    NotNfc,
    /// The output buffer is too small.
    Space,
    /// A token id outside the vocabulary.
    Token,
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    match b.get(4 * i..4 * i + 4) {
        Some([a, c, d, e]) => u32::from_le_bytes([*a, *c, *d, *e]),
        _ => 0,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Tokenizer<'a> {
    n_vocab: usize,
    byte_ids: &'a [u8],
    merges: &'a [u8],
    offsets: &'a [u8],
    added: &'a [u8],
    ranges: &'a [u8],
    decomp: &'a [u8],
    dpool: &'a [u8],
    comp: &'a [u8],
    pool: &'a [u8],
    ascii: [u8; 128],
}

impl<'a> Tokenizer<'a> {
    /// Parse and validate a blob. O(blob size); run once at admission.
    pub fn new(blob: &'a [u8]) -> Result<Self, TokError> {
        if blob.get(..4) != Some(&MAGIC[..]) {
            return Err(TokError::Table);
        }
        let h = |i| u32_at(blob, i) as usize;
        let (n_vocab, n_merges, n_added, n_ranges) = (h(1), h(2), h(3), h(4));
        let (n_decomp, n_dpool, n_comp) = (h(5), h(6), h(7));
        if n_decomp > (1 << 16) || n_dpool > (1 << 18) || n_comp > (1 << 16) {
            return Err(TokError::Table);
        }
        if !(256..=(1 << 24)).contains(&n_vocab) || n_merges >= n_vocab || n_added > 4096 || n_ranges > (1 << 20) {
            return Err(TokError::Table);
        }
        let mut at = 32usize;
        let mut take = |n: usize| -> Result<&'a [u8], TokError> {
            let s = blob.get(at..at.checked_add(n).ok_or(TokError::Table)?).ok_or(TokError::Table)?;
            at += n;
            Ok(s)
        };
        let byte_ids = take(256 * 4)?;
        let merges = take(n_merges * 16)?;
        let offsets = take((n_vocab + 1) * 4)?;
        let added = take(n_added * 4)?;
        let ranges = take(n_ranges * 12)?;
        let decomp = take(n_decomp * 8)?;
        let dpool = take(n_dpool * 4)?;
        let comp = take(n_comp * 12)?;
        let pool_len = u32_at(offsets, n_vocab) as usize;
        let pool = take(pool_len)?;
        if at != blob.len() {
            return Err(TokError::Table);
        }
        let mut t = Self { n_vocab, byte_ids, merges, offsets, added, ranges, decomp, dpool, comp, pool, ascii: [0; 128] };
        // Offsets monotone, tokens non-empty and bounded.
        for i in 0..n_vocab {
            let (a, b) = (u32_at(offsets, i), u32_at(offsets, i + 1));
            if a >= b || (b - a) as usize > MAX_TOKEN_BYTES {
                return Err(TokError::Table);
            }
        }
        if u32_at(offsets, 0) != 0 {
            return Err(TokError::Table);
        }
        // Each byte maps to a token whose text is exactly that byte.
        for b in 0..256usize {
            let id = u32_at(byte_ids, b) as usize;
            if t.bytes(id) != Some(&[b as u8][..]) {
                return Err(TokError::Table);
            }
        }
        // Merges: sorted and unique by pair, ids in range, ranks in range, and the result's text is the
        // concatenation of the two parts.
        let mut prev: Option<(u32, u32)> = None;
        for m in 0..n_merges {
            let (a, b, r, n) = (u32_at(merges, 4 * m), u32_at(merges, 4 * m + 1), u32_at(merges, 4 * m + 2), u32_at(merges, 4 * m + 3));
            if prev.is_some_and(|p| p >= (a, b)) || r as usize >= n_merges {
                return Err(TokError::Table);
            }
            prev = Some((a, b));
            let (Some(ta), Some(tb), Some(tn)) = (t.bytes(a as usize), t.bytes(b as usize), t.bytes(n as usize)) else { return Err(TokError::Table) };
            if tn.len() != ta.len() + tb.len() || tn.get(..ta.len()) != Some(ta) || tn.get(ta.len()..) != Some(tb) {
                return Err(TokError::Table);
            }
        }
        for i in 0..n_added {
            if u32_at(added, i) as usize >= n_vocab {
                return Err(TokError::Table);
            }
        }
        let mut last: Option<u32> = None;
        for i in 0..n_ranges {
            let (f, l) = (u32_at(ranges, 3 * i), u32_at(ranges, 3 * i + 1));
            if f > l || l > 0x10_ffff || last.is_some_and(|p| p >= f) {
                return Err(TokError::Table);
            }
            last = Some(l);
        }
        // Decompositions: sorted by code point, 1..=4 valid scalar values each, inside the pool.
        let scalar = |c: u32| c <= 0x10_ffff && !(0xd800..0xe000).contains(&c);
        let mut prev_cp: Option<u32> = None;
        for i in 0..n_decomp {
            let (cp, p) = (u32_at(decomp, 2 * i), u32_at(decomp, 2 * i + 1));
            let (start, len) = ((p & 0xff_ffff) as usize, (p >> 24) as usize);
            if prev_cp.is_some_and(|q| q >= cp) || !scalar(cp) || !(1..=4).contains(&len) || start + len > n_dpool {
                return Err(TokError::Table);
            }
            prev_cp = Some(cp);
        }
        if (0..n_dpool).any(|i| !scalar(u32_at(dpool, i))) {
            return Err(TokError::Table);
        }
        let mut prev_pair: Option<(u32, u32)> = None;
        for i in 0..n_comp {
            let (a, b, c) = (u32_at(comp, 3 * i), u32_at(comp, 3 * i + 1), u32_at(comp, 3 * i + 2));
            if prev_pair.is_some_and(|p| p >= (a, b)) || !scalar(a) || !scalar(b) || !scalar(c) {
                return Err(TokError::Table);
            }
            prev_pair = Some((a, b));
        }
        let mut ascii = [0u8; 128];
        for (c, a) in ascii.iter_mut().enumerate() {
            *a = t.class_search(c as u32) as u8;
        }
        t.ascii = ascii;
        Ok(t)
    }

    /// Number of token ids (regular and added).
    pub fn vocab(&self) -> usize {
        self.n_vocab
    }

    /// The bytes of one token.
    pub fn bytes(&self, id: usize) -> Option<&'a [u8]> {
        if id >= self.n_vocab {
            return None;
        }
        let (a, b) = (u32_at(self.offsets, id) as usize, u32_at(self.offsets, id + 1) as usize);
        self.pool.get(a..b)
    }

    /// True for added tokens (`<|im_start|>`, `<tool_call>`, …): never part of a constrained answer.
    pub fn is_added(&self, id: u32) -> bool {
        (0..self.added.len() / 4).any(|i| u32_at(self.added, i) == id)
    }

    /// Id of the added token with exactly this text, if any.
    pub fn added_id(&self, text: &[u8]) -> Option<u32> {
        (0..self.added.len() / 4).map(|i| u32_at(self.added, i)).find(|&id| self.bytes(id as usize) == Some(text))
    }

    fn class_search(&self, c: u32) -> u32 {
        let n = self.ranges.len() / 12;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (f, l) = (u32_at(self.ranges, 3 * mid), u32_at(self.ranges, 3 * mid + 1));
            if c < f {
                hi = mid;
            } else if c > l {
                lo = mid + 1;
            } else {
                return u32_at(self.ranges, 3 * mid + 2);
            }
        }
        0
    }

    /// Unicode class bits of a character (see the module documentation).
    pub fn class(&self, c: char) -> u32 {
        let c = c as u32;
        match self.ascii.get(c as usize) {
            Some(&a) => u32::from(a),
            None => self.class_search(c),
        }
    }

    fn merge(&self, a: u32, b: u32) -> Option<(u32, u32)> {
        let n = self.merges.len() / 16;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let k = (u32_at(self.merges, 4 * mid), u32_at(self.merges, 4 * mid + 1));
            match k.cmp(&(a, b)) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some((u32_at(self.merges, 4 * mid + 2), u32_at(self.merges, 4 * mid + 3))),
            }
        }
        None
    }

    /// Longest added token starting at `text[i..]`: (length, id).
    fn added_at(&self, text: &[u8], i: usize) -> Option<(usize, u32)> {
        let rest = text.get(i..)?;
        let mut best: Option<(usize, u32)> = None;
        for k in 0..self.added.len() / 4 {
            let id = u32_at(self.added, k);
            if let Some(t) = self.bytes(id as usize) {
                if rest.starts_with(t) && best.is_none_or(|(l, _)| t.len() > l) {
                    best = Some((t.len(), id));
                }
            }
        }
        best
    }

    fn ccc(&self, c: u32) -> u32 {
        match char::from_u32(c) {
            Some(ch) if c >= 0x300 => (self.class(ch) >> 8) & 0xff,
            _ => 0,
        }
    }

    fn decomposition(&self, c: u32) -> Option<&'a [u8]> {
        let n = self.decomp.len() / 8;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let cp = u32_at(self.decomp, 2 * mid);
            if c < cp {
                hi = mid;
            } else if c > cp {
                lo = mid + 1;
            } else {
                let p = u32_at(self.decomp, 2 * mid + 1);
                let (s, l) = ((p & 0xff_ffff) as usize, (p >> 24) as usize);
                return self.dpool.get(4 * s..4 * (s + l));
            }
        }
        None
    }

    fn compose(&self, a: u32, b: u32) -> Option<u32> {
        // Hangul: L + V → LV, LV + T → LVT (Unicode §3.12).
        if (0x1100..0x1113).contains(&a) && (0x1161..0x1176).contains(&b) {
            return Some(0xac00 + ((a - 0x1100) * 21 + (b - 0x1161)) * 28);
        }
        if (0xac00..0xd7a4).contains(&a) && (a - 0xac00) % 28 == 0 && (0x11a8..0x11c3).contains(&b) {
            return Some(a + (b - 0x11a7));
        }
        let n = self.comp.len() / 12;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let k = (u32_at(self.comp, 3 * mid), u32_at(self.comp, 3 * mid + 1));
            match k.cmp(&(a, b)) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(u32_at(self.comp, 3 * mid + 2)),
            }
        }
        None
    }

    /// NFC of `s` as UTF-8 into `buf`, using `cps` (≥ 4 × `s.len()` entries) as working space. Returns the
    /// byte count. `buf` needs at most 3 × `s.len()` bytes (the UAX #15 bound for NFC).
    pub fn nfc(&self, s: &str, cps: &mut [u32], buf: &mut [u8]) -> Result<usize, TokError> {
        // 1. Full canonical decomposition.
        let mut n = 0usize;
        let mut push = |c: u32, cps: &mut [u32]| -> Result<(), TokError> {
            *cps.get_mut(n).ok_or(TokError::Space)? = c;
            n += 1;
            Ok(())
        };
        for ch in s.chars() {
            let c = ch as u32;
            if (0xac00..0xd7a4).contains(&c) {
                let si = c - 0xac00;
                push(0x1100 + si / 588, cps)?;
                push(0x1161 + (si % 588) / 28, cps)?;
                if si % 28 != 0 {
                    push(0x11a7 + si % 28, cps)?;
                }
            } else if let Some(d) = self.decomposition(c) {
                for i in 0..d.len() / 4 {
                    push(u32_at(d, i), cps)?;
                }
            } else {
                push(c, cps)?;
            }
        }
        let cps = cps.get_mut(..n).ok_or(TokError::Space)?;
        // 2. Canonical ordering: stable sort of each run of non-starters by combining class.
        for i in 1..cps.len() {
            let mut j = i;
            while j > 0 {
                let (prev, cur) = (cps.get(j - 1).copied().unwrap_or(0), cps.get(j).copied().unwrap_or(0));
                let (cp, cc) = (self.ccc(prev), self.ccc(cur));
                if cc == 0 || cp <= cc {
                    break;
                }
                cps.swap(j - 1, j);
                j -= 1;
            }
        }
        // 3. Canonical composition (UAX #15 §1.3 / the reference algorithm).
        let mut kept = n.min(1);
        if n > 0 {
            let mut starter = 0usize;
            let mut last_class = self.ccc(cps.first().copied().unwrap_or(0));
            if last_class != 0 {
                last_class = 256; // a leading non-starter blocks composition
            }
            for i in 1..n {
                let ch = cps.get(i).copied().unwrap_or(0);
                let class = self.ccc(ch);
                let st = cps.get(starter).copied().unwrap_or(0);
                match self.compose(st, ch) {
                    Some(c) if last_class < class || last_class == 0 => {
                        if let Some(x) = cps.get_mut(starter) {
                            *x = c;
                        }
                    }
                    _ => {
                        if class == 0 {
                            starter = kept;
                        }
                        last_class = class;
                        if let Some(x) = cps.get_mut(kept) {
                            *x = ch;
                        }
                        kept += 1;
                    }
                }
            }
        }
        // 4. Back to UTF-8.
        let mut m = 0usize;
        for &c in cps.get(..kept).unwrap_or(&[]) {
            let ch = char::from_u32(c).ok_or(TokError::Table)?;
            let l = ch.len_utf8();
            ch.encode_utf8(buf.get_mut(m..m + l).ok_or(TokError::Space)?);
            m += l;
        }
        Ok(m)
    }

    /// UAX #15 quick check for NFC: true only if the text is certainly NFC.
    fn is_nfc(&self, s: &str) -> bool {
        let mut last_ccc = 0u32;
        for c in s.chars() {
            if (c as u32) < 0x300 {
                last_ccc = 0;
                continue;
            }
            let k = self.class(c);
            let ccc = (k >> 8) & 0xff;
            if k & (NFC_NO | NFC_MAYBE) != 0 || (ccc != 0 && last_ccc > ccc) {
                return false;
            }
            last_ccc = ccc;
        }
        true
    }

    /// Split `s` with the Qwen2 pre-tokenizer pattern, calling `piece(start, end)` (byte offsets).
    pub fn pretokenize(&self, s: &str, mut piece: impl FnMut(usize, usize) -> Result<(), TokError>) -> Result<(), TokError> {
        let b = s.as_bytes();
        let ch = |i: usize| s.get(i..).and_then(|r| r.chars().next());
        let next = |i: usize| i + ch(i).map_or(1, char::len_utf8);
        let is = |i: usize, bit: u32| ch(i).is_some_and(|c| self.class(c) & bit != 0);
        let crlf = |i: usize| matches!(b.get(i), Some(b'\r' | b'\n'));
        let other = |i: usize| ch(i).is_some_and(|c| self.class(c) & (LETTER | NUMBER | SPACE) == 0);
        let letters = |mut i: usize| {
            while i < b.len() && is(i, LETTER) {
                i = next(i);
            }
            i
        };
        let mut i = 0usize;
        while i < b.len() {
            let end = 'm: {
                // 1. (?i:'s|'t|'re|'ve|'m|'ll|'d)
                if b.get(i) == Some(&b'\'') {
                    let lc = |k: usize| ch(k).map(|c| if c == '\u{17f}' { 's' } else { c.to_ascii_lowercase() });
                    let (c1, c2) = (lc(i + 1), ch(i + 1).and_then(|c| lc(i + 1 + c.len_utf8())));
                    let l1 = ch(i + 1).map_or(0, char::len_utf8);
                    match (c1, c2) {
                        (Some('s' | 't' | 'm' | 'd'), _) => break 'm i + 1 + l1,
                        (Some('r'), Some('e')) | (Some('v'), Some('e')) | (Some('l'), Some('l')) => break 'm i + 2 + l1,
                        _ => {}
                    }
                }
                // 2. [^\r\n\p{L}\p{N}]?\p{L}+
                if !crlf(i) && !is(i, LETTER) && !is(i, NUMBER) && is(next(i), LETTER) {
                    break 'm letters(next(i));
                }
                if is(i, LETTER) {
                    break 'm letters(i);
                }
                // 3. \p{N}
                if is(i, NUMBER) {
                    break 'm next(i);
                }
                // 4. ' ?[^\s\p{L}\p{N}]+[\r\n]*'
                let start = if b.get(i) == Some(&b' ') && other(i + 1) { i + 1 } else { i };
                if other(start) {
                    let mut j = start;
                    while j < b.len() && other(j) {
                        j = next(j);
                    }
                    while crlf(j) {
                        j += 1;
                    }
                    break 'm j;
                }
                // Whitespace from here on: the run is i..j.
                let mut j = i;
                let mut last_crlf = None;
                while j < b.len() && is(j, SPACE) {
                    if crlf(j) {
                        last_crlf = Some(j);
                    }
                    j = next(j);
                }
                // 5. \s*[\r\n]+ : up to and including the last CR/LF of the run.
                if let Some(p) = last_crlf {
                    break 'm p + 1;
                }
                // 6. \s+(?!\S) : the whole run at the end of the text, else all but its last character.
                if j >= b.len() {
                    break 'm j;
                }
                let mut k = i;
                let mut prev = i;
                while k < j {
                    prev = k;
                    k = next(k);
                }
                if prev > i {
                    break 'm prev;
                }
                // 7. \s+
                j
            };
            let end = end.max(next(i)).min(b.len());
            piece(i, end)?;
            i = end;
        }
        Ok(())
    }

    /// BPE on one piece: its byte tokens are written at `out[n..]`, merged in place. Returns the new `n`.
    fn bpe(&self, piece: &[u8], out: &mut [u32], n: usize) -> Result<usize, TokError> {
        let buf = out.get_mut(n..n + piece.len()).ok_or(TokError::Space)?;
        for (o, &c) in buf.iter_mut().zip(piece) {
            *o = u32_at(self.byte_ids, usize::from(c));
        }
        let mut len = buf.len();
        loop {
            let mut best: Option<(u32, u32, u32, u32)> = None; // (rank, a, b, new)
            for w in buf.get(..len).unwrap_or(&[]).windows(2) {
                if let [a, b] = *w {
                    if let Some((r, new)) = self.merge(a, b) {
                        if best.is_none_or(|x| r < x.0) {
                            best = Some((r, a, b, new));
                        }
                    }
                }
            }
            let Some((_, a, b, new)) = best else { return Ok(n + len) };
            let (mut rd, mut wr) = (0usize, 0usize);
            while rd < len {
                let x = buf.get(rd).copied().unwrap_or(0);
                let tok = if rd + 1 < len && x == a && buf.get(rd + 1) == Some(&b) {
                    rd += 2;
                    new
                } else {
                    rd += 1;
                    x
                };
                if let Some(o) = buf.get_mut(wr) {
                    *o = tok;
                }
                wr += 1;
            }
            len = wr;
        }
    }

    /// Encode UTF-8 `text` into `out` (never more ids than bytes). Text that is not certainly NFC is refused
    /// with [`TokError::NotNfc`]; use [`Tokenizer::encode_nfc`] to normalise it instead. Returns the id count.
    pub fn encode(&self, text: &[u8], out: &mut [u32]) -> Result<usize, TokError> {
        self.encode_impl(text, out, None)
    }

    /// Encode with NFC normalisation, as the model's tokenizer does. `cps` (≥ 4 × `text.len()`) and `buf`
    /// (≥ 3 × `text.len()`) are working space, used only for text that the quick check cannot pass; `out`
    /// needs ≥ 3 × `text.len()` entries in that case. Returns the id count.
    pub fn encode_nfc(&self, text: &[u8], out: &mut [u32], cps: &mut [u32], buf: &mut [u8]) -> Result<usize, TokError> {
        self.encode_impl(text, out, Some((cps, buf)))
    }

    fn encode_part(&self, part: &str, out: &mut [u32], n: &mut usize) -> Result<(), TokError> {
        self.pretokenize(part, |a, b| {
            *n = self.bpe(part.as_bytes().get(a..b).unwrap_or(&[]), out, *n)?;
            Ok(())
        })
    }

    fn encode_impl(&self, text: &[u8], out: &mut [u32], mut norm: Option<(&mut [u32], &mut [u8])>) -> Result<usize, TokError> {
        let s = core::str::from_utf8(text).map_err(|_| TokError::Utf8)?;
        let mut n = 0usize;
        let (mut i, mut seg) = (0usize, 0usize);
        while i <= text.len() {
            let hit = if i < text.len() { self.added_at(text, i) } else { None };
            if hit.is_some() || i == text.len() {
                let part = s.get(seg..i).ok_or(TokError::Utf8)?;
                if self.is_nfc(part) {
                    self.encode_part(part, out, &mut n)?;
                } else {
                    let (cps, buf) = norm.as_mut().ok_or(TokError::NotNfc)?;
                    let m = self.nfc(part, cps, buf)?;
                    let normalised = core::str::from_utf8(buf.get(..m).ok_or(TokError::Space)?).map_err(|_| TokError::Table)?;
                    self.encode_part(normalised, out, &mut n)?;
                }
                match hit {
                    Some((len, id)) => {
                        *out.get_mut(n).ok_or(TokError::Space)? = id;
                        n += 1;
                        i += len;
                        seg = i;
                    }
                    None => break,
                }
            } else {
                i += 1;
            }
        }
        Ok(n)
    }

    /// Decode ids into bytes (a token may end mid-character; the caller joins). Returns the byte count.
    pub fn decode(&self, ids: &[u32], out: &mut [u8]) -> Result<usize, TokError> {
        let mut n = 0usize;
        for &id in ids {
            let t = self.bytes(id as usize).ok_or(TokError::Token)?;
            out.get_mut(n..n + t.len()).ok_or(TokError::Space)?.copy_from_slice(t);
            n += t.len();
        }
        Ok(n)
    }
}
