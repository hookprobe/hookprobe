// SPDX-License-Identifier: AGPL-3.0-only
//! Build-host side of the tokenizer: model tokenizer definition → `neuro_lm::tok` blob.
//!
//! Input today is HF `tokenizer.json` (byte-level BPE, as Qwen2/Qwen3 ship it). The converter will feed the
//! same [`Source`] from GGUF metadata (`tokenizer.ggml.tokens` / `merges`), so the device tokenizer is
//! built from the exact file Neuro validated.
use neuro_lm::tok::{LETTER, MAGIC, NFC_MAYBE, NFC_NO, NUMBER, SPACE};
use std::collections::HashMap;

/// A byte-level BPE vocabulary in raw bytes.
#[derive(Debug, Clone)]
pub struct Source {
    /// Token bytes by id (regular tokens in raw bytes; added tokens as their UTF-8 text).
    pub tokens: Vec<Vec<u8>>,
    /// Merges by rank: (left id, right id).
    pub merges: Vec<(u32, u32)>,
    /// Ids of added tokens, matched on the raw text before pre-tokenization.
    pub added: Vec<u32>,
}

/// GPT-2's byte ↔ printable character mapping used by byte-level BPE vocabularies.
pub fn byte_to_char() -> [char; 256] {
    let mut map = ['\0'; 256];
    let mut n = 0u32;
    for b in 0..256u32 {
        let printable = (0x21..=0x7e).contains(&b) || (0xa1..=0xac).contains(&b) || (0xae..=0xff).contains(&b);
        map[b as usize] = if printable {
            char::from_u32(b).unwrap()
        } else {
            n += 1;
            char::from_u32(255 + n).unwrap()
        };
    }
    map
}

/// Read a HF `tokenizer.json` with a byte-level BPE model.
pub fn from_hf_json(json: &str) -> Result<Source, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let model = &v["model"];
    if model["type"] != "BPE" {
        return Err("model is not BPE".into());
    }
    let inv: HashMap<char, u8> = byte_to_char().iter().enumerate().map(|(b, &c)| (c, b as u8)).collect();
    let vocab = model["vocab"].as_object().ok_or("no vocab")?;
    let mut by_id: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut id_of: HashMap<&str, u32> = HashMap::new();
    for (s, id) in vocab {
        let id = id.as_u64().ok_or("bad id")? as u32;
        let bytes = s.chars().map(|c| inv.get(&c).copied().ok_or_else(|| format!("token {s:?} has a non byte-level char"))).collect::<Result<Vec<u8>, _>>()?;
        by_id.insert(id, bytes);
        id_of.insert(s.as_str(), id);
    }
    let mut added = vec![];
    for t in v["added_tokens"].as_array().ok_or("no added_tokens")? {
        let id = t["id"].as_u64().ok_or("bad added id")? as u32;
        let content = t["content"].as_str().ok_or("bad added content")?;
        for flag in ["lstrip", "rstrip", "single_word", "normalized"] {
            if t[flag] == true {
                return Err(format!("added token {content:?} uses {flag}, not supported"));
            }
        }
        if by_id.insert(id, content.as_bytes().to_vec()).is_some() {
            return Err(format!("added token id {id} collides with the vocabulary"));
        }
        added.push(id);
    }
    let n = by_id.keys().max().map_or(0, |m| m + 1);
    let tokens = (0..n).map(|i| by_id.remove(&i).ok_or_else(|| format!("id {i} missing"))).collect::<Result<Vec<_>, _>>()?;
    let mut merges = vec![];
    for m in model["merges"].as_array().ok_or("no merges")? {
        let (a, b) = match m {
            serde_json::Value::Array(p) if p.len() == 2 => (p[0].as_str().unwrap_or(""), p[1].as_str().unwrap_or("")),
            serde_json::Value::String(s) => s.split_once(' ').ok_or("bad merge")?,
            _ => return Err("bad merge".into()),
        };
        let (ia, ib) = (id_of.get(a).ok_or_else(|| format!("merge part {a:?} not in vocab"))?, id_of.get(b).ok_or_else(|| format!("merge part {b:?} not in vocab"))?);
        merges.push((*ia, *ib));
    }
    Ok(Source { tokens, merges, added })
}

/// Unicode class ranges for the device: `\p{L}`, `\p{N}`, `\s` (as the `regex` crate defines them, which is
/// also what the reference pre-tokenizer uses), NFC quick-check No/Maybe and canonical combining class.
pub fn unicode_ranges() -> Vec<(u32, u32, u32)> {
    use unicode_normalization::char::canonical_combining_class;
    use unicode_normalization::{is_nfc_quick, IsNormalized};
    let (l, n, s) = (regex::Regex::new(r"^\p{L}$").unwrap(), regex::Regex::new(r"^\p{N}$").unwrap(), regex::Regex::new(r"^\s$").unwrap());
    let mut out: Vec<(u32, u32, u32)> = vec![];
    let mut buf = [0u8; 4];
    for cp in 0..=0x10_ffffu32 {
        let Some(c) = char::from_u32(cp) else { continue };
        let t = c.encode_utf8(&mut buf);
        let mut k = 0;
        if l.is_match(t) {
            k |= LETTER;
        }
        if n.is_match(t) {
            k |= NUMBER;
        }
        if s.is_match(t) {
            k |= SPACE;
        }
        match is_nfc_quick(std::iter::once(c)) {
            IsNormalized::No => k |= NFC_NO,
            IsNormalized::Maybe => k |= NFC_MAYBE,
            IsNormalized::Yes => {}
        }
        k |= u32::from(canonical_combining_class(c)) << 8;
        if k == 0 {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.1 + 1 == cp && last.2 == k => last.1 = cp,
            _ => out.push((cp, cp, k)),
        }
    }
    out
}

/// Assemble the blob (layout in `neuro_lm::tok`).
pub fn blob(src: &Source, ranges: &[(u32, u32, u32)], nfc: &(Vec<(u32, Vec<u32>)>, Vec<(u32, u32, u32)>)) -> Result<Vec<u8>, String> {
    let (decomp, comp) = nfc;
    let n_dpool: usize = decomp.iter().map(|d| d.1.len()).sum();
    let n = src.tokens.len();
    let mut byte_ids = [u32::MAX; 256];
    for (id, t) in src.tokens.iter().enumerate() {
        if let [b] = t[..] {
            if !src.added.contains(&(id as u32)) && byte_ids[b as usize] == u32::MAX {
                byte_ids[b as usize] = id as u32;
            }
        }
    }
    if byte_ids.contains(&u32::MAX) {
        return Err("a byte has no token".into());
    }
    let mut index: HashMap<Vec<u8>, u32> = HashMap::new();
    for (id, t) in src.tokens.iter().enumerate() {
        if !src.added.contains(&(id as u32)) {
            index.entry(t.clone()).or_insert(id as u32);
        }
    }
    let mut merges = vec![];
    for (rank, &(a, b)) in src.merges.iter().enumerate() {
        let mut cat = src.tokens[a as usize].clone();
        cat.extend_from_slice(&src.tokens[b as usize]);
        let new = *index.get(&cat).ok_or_else(|| format!("merge {rank} result not in vocab"))?;
        merges.push((a, b, rank as u32, new));
    }
    merges.sort();
    // Keep the first (lowest-rank) of duplicate pairs, as HF does.
    merges.dedup_by(|x, y| (x.0, x.1) == (y.0, y.1));
    let mut out = vec![];
    let put = |v: u32, o: &mut Vec<u8>| o.extend_from_slice(&v.to_le_bytes());
    out.extend_from_slice(&MAGIC);
    for v in [n as u32, merges.len() as u32, src.added.len() as u32, ranges.len() as u32, decomp.len() as u32, n_dpool as u32, comp.len() as u32] {
        put(v, &mut out);
    }
    for v in byte_ids {
        put(v, &mut out);
    }
    for m in &merges {
        for v in [m.0, m.1, m.2, m.3] {
            put(v, &mut out);
        }
    }
    let mut off = 0u32;
    put(0, &mut out);
    for t in &src.tokens {
        off += t.len() as u32;
        put(off, &mut out);
    }
    for &a in &src.added {
        put(a, &mut out);
    }
    for r in ranges {
        for v in [r.0, r.1, r.2] {
            put(v, &mut out);
        }
    }
    let mut at = 0u32;
    for (cp, d) in decomp {
        put(*cp, &mut out);
        put(at | ((d.len() as u32) << 24), &mut out);
        at += d.len() as u32;
    }
    for (_, d) in decomp {
        for &c in d {
            put(c, &mut out);
        }
    }
    for &(a, b, c) in comp {
        for v in [a, b, c] {
            put(v, &mut out);
        }
    }
    for t in &src.tokens {
        out.extend_from_slice(t);
    }
    Ok(out)
}

/// NFC tables: full canonical decompositions (cp, code points) and primary compositions (a, b, composite),
/// both without Hangul (the device does Hangul algorithmically).
pub fn nfc_tables() -> (Vec<(u32, Vec<u32>)>, Vec<(u32, u32, u32)>) {
    use unicode_normalization::char::{compose, decompose_canonical};
    use unicode_normalization::{is_nfc_quick, IsNormalized};
    let hangul = |c: u32| (0xac00..0xd7a4).contains(&c) || (0x1100..0x1200).contains(&c);
    let mut decomp = vec![];
    let mut second = vec![];
    for cp in 0..=0x10_ffffu32 {
        let Some(c) = char::from_u32(cp) else { continue };
        if is_nfc_quick(std::iter::once(c)) == IsNormalized::Maybe {
            second.push(c);
        }
        if hangul(cp) {
            continue;
        }
        let mut d = vec![];
        decompose_canonical(c, |x| d.push(x as u32));
        if d != [cp] {
            decomp.push((cp, d));
        }
    }
    let mut comp = vec![];
    for cp in 0..=0x10_ffffu32 {
        let Some(a) = char::from_u32(cp) else { continue };
        for &b in &second {
            if let Some(x) = compose(a, b) {
                if !hangul(cp) && !hangul(x as u32) {
                    comp.push((cp, b as u32, x as u32));
                }
            }
        }
    }
    comp.sort();
    (decomp, comp)
}
