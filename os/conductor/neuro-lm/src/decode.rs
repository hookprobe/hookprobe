// SPDX-License-Identifier: AGPL-3.0-only
//! Evidence-closed greedy decoding for the explainer, with two exact speed-ups.
//!
//! **Constraint.** Every candidate token is checked against the answer automaton of `neuro_contract` (the
//! same one the verifier parses with). Greedy decoding picks the highest logit among allowed tokens; end of
//! generation is allowed only when the answer is complete; added tokens never appear inside an answer. This
//! is what llama-server does with Neuro's `json_schema` response format at temperature 0.
//!
//! **Head pruning** (exact). Outside free-text strings the grammar allows few tokens. The decoder lists them
//! first and computes only those rows of the output head (18 % of Qwen3-1.7B's bytes per token). The rows it
//! computes are bit-identical to a full head, so the choice is identical.
//!
//! **Verified speculation** (exact). Drafts come from text the grammar forces (key names, the rest of an
//! enum or id) and from n-gram lookup in the prompt and the answer so far (copied fact ids, names, numbers).
//! One batched forward pass checks them: each column is bit-identical to a one-token pass, and a draft token
//! is kept only if it is the masked greedy choice. The output is therefore exactly the sequential output;
//! only the number of passes over the weights goes down.

use crate::qwen3::{Head, Kv, Model, Work, MAX_BATCH};
use crate::tok::Tokenizer;
use crate::LmError;
use neuro_contract::Machine;
use neuro_kernels::Simd;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Use a pruned head when at most this many tokens are allowed (0 disables pruning).
    pub prune_max: usize,
    /// Draft tokens per verification pass (0 disables speculation; at most `batch − 1` of the `Work`).
    pub draft_max: usize,
    /// Most tokens to generate.
    pub max_new: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Forward passes after the prompt (each reads the weights once).
    pub passes: u32,
    /// Tokens generated (end of generation included).
    pub tokens: u32,
    /// Passes that computed a pruned head, and the head rows they computed in total.
    pub pruned_passes: u32,
    pub pruned_rows: u64,
    /// Draft tokens proposed, and accepted by verification.
    pub drafted: u32,
    pub accepted: u32,
    /// Prompt passes (batched).
    pub prefill_passes: u32,
}

/// Is `id` allowed next?
fn allowed(m: &Machine, tok: &Tokenizer, eog: &[u32], id: u32) -> bool {
    if eog.contains(&id) {
        return m.accepting();
    }
    if tok.is_added(id) {
        return false;
    }
    match tok.bytes(id as usize) {
        Some(b) => m.accepts(b),
        None => false,
    }
}

/// Masked greedy choice: the highest logit among allowed tokens, lowest id on ties.
fn pick(logits: &[i64], m: &Machine, tok: &Tokenizer, eog: &[u32]) -> Option<u32> {
    // Fast path: the unconstrained argmax is usually allowed.
    let mut best: Option<(usize, i64)> = None;
    for (i, &v) in logits.iter().enumerate() {
        if best.is_none_or(|(_, b)| v > b) {
            best = Some((i, v));
        }
    }
    let (i, _) = best?;
    if allowed(m, tok, eog, i as u32) {
        return Some(i as u32);
    }
    let mut best: Option<(u32, i64)> = None;
    for (i, &v) in logits.iter().enumerate() {
        if best.is_none_or(|(_, b)| v > b) && allowed(m, tok, eog, i as u32) {
            best = Some((i as u32, v));
        }
    }
    best.map(|b| b.0)
}

/// Every allowed token id, ascending, into `list` (returns the count; stops at the list's capacity, which
/// the caller treats as "too many to prune").
fn list_allowed(m: &Machine, tok: &Tokenizer, eog: &[u32], vocab: usize, list: &mut [u32]) -> usize {
    let mut n = 0usize;
    for id in 0..vocab as u32 {
        if allowed(m, tok, eog, id) {
            match list.get_mut(n) {
                Some(s) => *s = id,
                None => return n + 1,
            }
            n += 1;
        }
    }
    n
}

/// Bytes the grammar forces from `m` (one allowed byte at each step), at most `out.len()`.
fn forced_bytes(m: &Machine, out: &mut [u8]) -> usize {
    let mut m = *m;
    let mut n = 0usize;
    while n < out.len() {
        let mut only: Option<u8> = None;
        let mut count = 0u32;
        for b in 0..=255u8 {
            if m.accepts(&[b]) {
                count += 1;
                only = Some(b);
                if count > 1 {
                    break;
                }
            }
        }
        match (count, only) {
            (1, Some(b)) => {
                if let Some(s) = out.get_mut(n) {
                    *s = b;
                }
                m.feed(&[b]);
                n += 1;
            }
            _ => break,
        }
    }
    n
}

/// Draft up to `max` tokens: grammar-forced text first, else the tokens that followed the most recent
/// earlier occurrence of the last 3 (or 2) tokens in `history`. Drafts are trimmed where the grammar
/// would refuse them.
fn draft(m: &Machine, tok: &Tokenizer, eog: &[u32], history: &[u32], max: usize, out: &mut [u32]) -> usize {
    let max = max.min(out.len());
    if max == 0 {
        return 0;
    }
    let mut n = 0usize;
    let mut fb = [0u8; 48];
    let nf = forced_bytes(m, &mut fb);
    if nf >= 2 {
        let mut ids = [0u32; 48];
        if let Ok(k) = tok.encode(fb.get(..nf).unwrap_or(&[]), &mut ids) {
            for (o, &t) in out.iter_mut().zip(ids.iter().take(k.min(max))) {
                *o = t;
                n += 1;
            }
        }
    }
    if n == 0 {
        'ngram: for g in [3usize, 2] {
            if history.len() <= g {
                continue;
            }
            let tail = history.get(history.len() - g..).unwrap_or(&[]);
            for start in (0..history.len() - g).rev() {
                if history.get(start..start + g) == Some(tail) {
                    for (o, &t) in out.iter_mut().zip(history.iter().skip(start + g).take(max)) {
                        *o = t;
                        n += 1;
                    }
                    if n > 0 {
                        break 'ngram;
                    }
                }
            }
        }
    }
    // Keep only the grammar-valid prefix of the draft.
    let mut mm = *m;
    let mut k = 0usize;
    while k < n {
        let t = out.get(k).copied().unwrap_or(0);
        if eog.contains(&t) || tok.is_added(t) || !tok.bytes(t as usize).is_some_and(|b| mm.feed(b)) {
            break;
        }
        k += 1;
    }
    k
}

/// Feed `prompt`, then generate an answer under the contract. `history` must hold at least
/// `prompt.len() + opts.max_new` entries (prompt and answer, for n-gram drafts); `list` is scratch for the
/// allowed-token list (its length bounds pruning). Writes the generated ids to `out`; returns their count.
#[allow(clippy::too_many_arguments)]
pub fn generate_closed(model: &Model, simd: Simd, tok: &Tokenizer, prompt: &[u32], eog: &[u32], mut machine: Machine, kv: &mut Kv, work: &mut Work, history: &mut [u32], list: &mut [u32], opts: Options, out: &mut [u32]) -> Result<(usize, Stats), LmError> {
    let vocab = model.dims.vocab.min(tok.vocab());
    let mut st = Stats::default();
    if prompt.is_empty() || history.len() < prompt.len() + opts.max_new {
        return Err(LmError::Work);
    }
    history.get_mut(..prompt.len()).ok_or(LmError::Work)?.copy_from_slice(prompt);
    let mut hlen = prompt.len();
    // Prompt in batches; the logits of its last position give the first token.
    let b = work.batch();
    st.prefill_passes = prompt.len().div_ceil(b) as u32;
    model.prefill(simd, prompt, kv, work)?;
    let last = (prompt.len() - 1) % b;
    let first = pick(work.logits_of(last, model.dims.vocab).get(..vocab).ok_or(LmError::Work)?, &machine, tok, eog).ok_or(LmError::Token)?;
    let mut next = first;
    let mut pos = prompt.len();
    let mut n = 0usize;
    let draft_max = opts.draft_max.min(b.saturating_sub(1)).min(MAX_BATCH - 1);
    loop {
        // Commit `next`.
        *out.get_mut(n).ok_or(LmError::Work)? = next;
        n += 1;
        st.tokens += 1;
        if let Some(h) = history.get_mut(hlen) {
            *h = next;
            hlen += 1;
        }
        if eog.contains(&next) {
            break;
        }
        if !machine.feed(tok.bytes(next as usize).ok_or(LmError::Token)?) {
            return Err(LmError::Token);
        }
        if n >= opts.max_new || n >= out.len() || pos + 1 >= model.dims.max_ctx {
            break;
        }
        // Drafts, verified in one batched pass.
        let mut d = [0u32; MAX_BATCH];
        let nd = if draft_max > 0 { draft(&machine, tok, eog, history.get(..hlen).unwrap_or(&[]), draft_max.min(opts.max_new - n).min(model.dims.max_ctx - pos - 1), &mut d) } else { 0 };
        if nd > 0 {
            let mut toks = [0usize; MAX_BATCH];
            toks[0] = next as usize;
            for (t, &x) in toks.iter_mut().skip(1).zip(d.iter().take(nd)) {
                *t = x as usize;
            }
            model.forward(simd, toks.get(..=nd).ok_or(LmError::Work)?, pos, kv, work, Head::All)?;
            st.passes += 1;
            st.drafted += nd as u32;
            // Column j predicts the token after toks[..=j].
            let mut m = machine;
            let mut j = 0usize;
            loop {
                let p = pick(work.logits_of(j, model.dims.vocab).get(..vocab).ok_or(LmError::Work)?, &m, tok, eog).ok_or(LmError::Token)?;
                if j < nd && Some(&p) == d.get(j) {
                    // Draft confirmed: commit it and continue with the next column.
                    st.accepted += 1;
                    *out.get_mut(n).ok_or(LmError::Work)? = p;
                    n += 1;
                    st.tokens += 1;
                    if let Some(h) = history.get_mut(hlen) {
                        *h = p;
                        hlen += 1;
                    }
                    if !m.feed(tok.bytes(p as usize).ok_or(LmError::Token)?) {
                        return Err(LmError::Token);
                    }
                    j += 1;
                    if n >= opts.max_new || n >= out.len() {
                        return Ok((n, st));
                    }
                    continue;
                }
                // First disagreement (or drafts used up): p is the next token after toks[..=j].
                machine = m;
                pos += j + 1;
                next = p;
                break;
            }
            continue;
        }
        // One token, with a pruned head where the grammar allows few tokens.
        let prune = opts.prune_max > 0 && !machine.in_free_text();
        let cap = list.len().min(opts.prune_max);
        let count = if prune { list_allowed(&machine, tok, eog, vocab, list.get_mut(..cap).ok_or(LmError::Work)?) } else { usize::MAX };
        if count <= cap {
            let rows = list.get(..count).ok_or(LmError::Work)?;
            model.forward(simd, &[next as usize], pos, kv, work, Head::Rows(rows))?;
            st.pruned_passes += 1;
            st.pruned_rows += count as u64;
            let lg = work.logits_of(0, model.dims.vocab);
            let mut best: Option<(u32, i64)> = None;
            for &id in rows {
                let v = lg.get(id as usize).copied().unwrap_or(i64::MIN);
                if best.is_none_or(|(_, bv)| v > bv) {
                    best = Some((id, v));
                }
            }
            next = best.ok_or(LmError::Token)?.0;
        } else {
            model.forward(simd, &[next as usize], pos, kv, work, Head::All)?;
            next = pick(work.logits_of(0, model.dims.vocab).get(..vocab).ok_or(LmError::Work)?, &machine, tok, eog).ok_or(LmError::Token)?;
        }
        st.passes += 1;
        pos += 1;
    }
    Ok((n, st))
}
