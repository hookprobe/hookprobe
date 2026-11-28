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
/// NFC tables: (code point, full canonical decomposition) and (a, b, primary composite).
pub type NfcTables = (Vec<(u32, Vec<u32>)>, Vec<(u32, u32, u32)>);

pub fn blob(src: &Source, ranges: &[(u32, u32, u32)], nfc: &NfcTables) -> Result<Vec<u8>, String> {
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
pub fn nfc_tables() -> NfcTables {
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

/// Read the tokenizer from GGUF metadata as llama.cpp's converter writes it (`tokenizer.ggml.model` =
/// "gpt2", byte-level tokens, "a b" merges). Control (3) and user-defined (4) tokens are added tokens,
/// matched on the raw text; unused padding entries (5) stay in the vocabulary but are never produced.
pub fn from_gguf(g: &neuro_gguf::Gguf) -> Result<Source, String> {
    if g.get_str(b"tokenizer.ggml.model") != Some(b"gpt2") {
        return Err("tokenizer.ggml.model is not gpt2 (byte-level BPE)".into());
    }
    let toks = g.get_array(b"tokenizer.ggml.tokens").ok_or("no tokenizer.ggml.tokens")?;
    let types = g.get_array(b"tokenizer.ggml.token_type").ok_or("no tokenizer.ggml.token_type")?;
    let merges = g.get_array(b"tokenizer.ggml.merges").ok_or("no tokenizer.ggml.merges")?;
    if types.len != toks.len {
        return Err("token_type length differs from tokens".into());
    }
    let inv: HashMap<char, u8> = byte_to_char().iter().enumerate().map(|(b, &c)| (c, b as u8)).collect();
    let mut tokens = vec![];
    let mut added = vec![];
    let mut id_of: HashMap<Vec<u8>, u32> = HashMap::new();
    for (i, t) in toks.strings().enumerate() {
        let s = std::str::from_utf8(t).map_err(|e| e.to_string())?;
        let ty = types.int(i as u64).ok_or("bad token_type")?;
        let bytes = match ty {
            1 => s.chars().map(|c| inv.get(&c).copied().ok_or_else(|| format!("token {i} {s:?} is not byte-level"))).collect::<Result<Vec<u8>, _>>()?,
            3 | 4 => {
                added.push(i as u32);
                t.to_vec()
            }
            5 => t.to_vec(),
            other => return Err(format!("token {i} has unsupported type {other}")),
        };
        if ty == 1 {
            id_of.entry(t.to_vec()).or_insert(i as u32);
        }
        tokens.push(bytes);
    }
    let mut ms = vec![];
    for m in merges.strings() {
        let s = std::str::from_utf8(m).map_err(|e| e.to_string())?;
        let (a, b) = s.split_once(' ').ok_or_else(|| format!("bad merge {s:?}"))?;
        let ia = *id_of.get(a.as_bytes()).ok_or_else(|| format!("merge part {a:?} not in vocab"))?;
        let ib = *id_of.get(b.as_bytes()).ok_or_else(|| format!("merge part {b:?} not in vocab"))?;
        ms.push((ia, ib));
    }
    Ok(Source { tokens, merges: ms, added })
}

// ------------------------------------------------------------------------------------------- model bundles

/// A GGUF file with the same metadata and only the tensors `keep` accepts, laid out again. Build side.
pub fn gguf_keeping(g: &neuro_gguf::Gguf, keep: impl Fn(&neuro_gguf::Tensor) -> bool) -> Vec<u8> {
    let align = g.alignment as usize;
    let mut kept = vec![];
    g.for_each_tensor(|t| {
        if keep(&t) {
            kept.push(t);
        }
    });
    let mut out = b"GGUF".to_vec();
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&(kept.len() as u64).to_le_bytes());
    out.extend_from_slice(&g.kv_count().to_le_bytes());
    out.extend_from_slice(g.kv_bytes());
    let mut data: Vec<u8> = vec![];
    for t in &kept {
        while !data.len().is_multiple_of(align) {
            data.push(0);
        }
        out.extend_from_slice(&(t.name.len() as u64).to_le_bytes());
        out.extend_from_slice(t.name);
        out.extend_from_slice(&(t.n_dims as u32).to_le_bytes());
        for d in t.dims.iter().take(t.n_dims) {
            out.extend_from_slice(&d.to_le_bytes());
        }
        out.extend_from_slice(&t.ty.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        data.extend_from_slice(t.data);
    }
    while !out.len().is_multiple_of(align) {
        out.push(0);
    }
    out.extend_from_slice(&data);
    out
}

/// The model's matrices in the packed layout, in the order and alignment of `neuro_gguf::qwen3::packed_shapes`,
/// and the GGUF file without them. Refuses a model whose output head is not tied to the embedding.
pub fn packed_parts(g: &neuro_gguf::Gguf, h: &neuro_gguf::qwen3::Hparams) -> Result<(Vec<u8>, Vec<u8>), String> {
    use neuro_gguf::qwen3::{layer, PACK_ALIGN};
    if g.tensor(b"output.weight").is_some() {
        return Err("the output head is not tied to the embedding; a packed section does not carry one".into());
    }
    let d = h.dims;
    let mut out: Vec<u8> = vec![];
    let mut put = |m: &neuro_lm::qwen3::Mat| -> Result<(), String> {
        while !out.len().is_multiple_of(PACK_ALIGN) {
            out.push(0);
        }
        let at = out.len();
        out.resize(at + neuro_kernels::q8::packed_bytes(m.rows, m.cols), 0);
        m.pack_into(&mut out[at..]).map(|_| ()).ok_or_else(|| "a matrix does not pack".to_string())
    };
    let embed = g.tensor(b"token_embd.weight").ok_or("no embedding")?;
    put(&neuro_lm::qwen3::Mat::gguf(d.vocab, d.d_model, embed.data))?;
    for i in 0..d.n_layers {
        let l = layer(g, h, i).map_err(|e| format!("layer {i}: {e:?}"))?;
        for m in [&l.wq, &l.wk, &l.wv, &l.wo, &l.w_gate, &l.w_up, &l.w_down] {
            put(m)?;
        }
    }
    // The file keeps everything that is not one of those matrices: metadata, tokenizer, norm vectors.
    let is_matrix = |name: &[u8]| name == b"token_embd.weight" || (name.starts_with(b"blk.") && [&b".attn_q.weight"[..], b".attn_k.weight", b".attn_v.weight", b".attn_output.weight", b".ffn_gate.weight", b".ffn_up.weight", b".ffn_down.weight"].iter().any(|s| name.ends_with(s)));
    Ok((out, gguf_keeping(g, |t| !is_matrix(t.name))))
}

/// A bundle from its four sections (`neuro_gguf::bundle`): model file, tokenizer tables, RoPE pairs, packed
/// matrices (empty when the file carries them).
pub fn bundle(parts: [&[u8]; 4]) -> Option<Vec<u8>> {
    use neuro_gguf::bundle::{layout, write_preamble};
    let lens = [parts[0].len(), parts[1].len(), parts[2].len(), parts[3].len()];
    let (offs, total) = layout(lens)?;
    let mut b = vec![0u8; total];
    write_preamble(lens, &mut b)?;
    for (o, part) in offs.iter().zip(parts) {
        b.get_mut(*o..*o + part.len())?.copy_from_slice(part);
    }
    Some(b)
}

