// SPDX-License-Identifier: AGPL-3.0-only
//! A language model out of the signed container: the last step of the one load path.
//!
//! `neuro_hnx::Loader` verifies the signature, the manifest and every segment of an HNX file. For a payload of
//! kind [`neuro_hnx::kind::GGUF_LM`] the verified bytes are a GGUF file, and for [`neuro_hnx::kind::LM_BUNDLE`] a
//! bundle ([`crate::bundle`]) holding that file and its tables; [`admit`] opens it, reads the Qwen3
//! hyperparameters for the context the manifest declares, and checks that the manifest told admission the
//! truth about memory. A file cannot under-declare what it needs: the numbers are recomputed here from the
//! file itself with [`manifest_for`], the same function the build side uses.
//!
//! What the manifest of a language model means:
//! - `max_context`: the context the device runs it at (not more than it was trained for);
//! - `state_bytes_per_session`: the KV cache for that context;
//! - `arena_bytes`: scratch for one forward pass of the largest batch, plus the RoPE table;
//! - `bytes_per_token`: the tensor bytes in the file, an upper bound of what one token reads;
//! - `macs_per_run`: 0 (work is per token, not per run).

use crate::bundle::{Bundle, BundleError};
use crate::qwen3::{hparams, BindError, Hparams};
use crate::{Gguf, GgufError};
use neuro_hnx::{kind, Loader, Manifest, Refusal};
use neuro_lm::qwen3::{Work, MAX_BATCH};
use neuro_lm::tok::Tokenizer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// The container refused: incomplete, failed, or not a language model.
    Container(Refusal),
    Bundle(BundleError),
    Gguf(GgufError),
    Bind(BindError),
    /// A size does not fit the manifest's fields.
    Size,
    /// The manifest in the signed header is not what the file needs.
    ManifestMismatch,
    /// The bundle's tables do not fit its model: RoPE rows for another context or head size, or tokenizer
    /// tables that do not parse or have another vocabulary size.
    Tables,
}

/// What the device runs from, all borrowed from the verified region.
pub struct Admitted<'r> {
    pub gguf: Gguf<'r>,
    pub hparams: Hparams,
    /// The tables of a bundle ([`kind::LM_BUNDLE`]); `None` for a bare GGUF payload, whose tables the caller
    /// must supply from elsewhere.
    pub bundle: Option<Bundle<'r>>,
}

/// The manifest a GGUF language model needs at context `max_ctx`, as a bare payload of kind `GGUF_LM`.
pub fn manifest_for(file: &[u8], max_ctx: usize) -> Result<Manifest, AdmitError> {
    manifest(file, file.len(), max_ctx)
}

/// The manifest of a bundle of kind `LM_BUNDLE`: that of its model, with the bundle's length as the payload.
pub fn manifest_for_bundle(bundle: &[u8], max_ctx: usize) -> Result<Manifest, AdmitError> {
    let b = Bundle::open(bundle).map_err(AdmitError::Bundle)?;
    manifest(b.gguf, bundle.len(), max_ctx)
}

fn manifest(file: &[u8], payload_len: usize, max_ctx: usize) -> Result<Manifest, AdmitError> {
    let g = Gguf::open(file).map_err(AdmitError::Gguf)?;
    let h = hparams(&g, max_ctx).map_err(AdmitError::Bind)?;
    let d = &h.dims;
    let (kv_vals, kv_shifts) = d.kv_len();
    let state = kv_vals.checked_mul(2).and_then(|v| v.checked_add(kv_shifts)).ok_or(AdmitError::Size)?;
    let (a, b, c, e) = Work::lens(d, MAX_BATCH);
    let rope = d.max_ctx.checked_mul(d.head_dim / 2).and_then(|n| n.checked_mul(8)).ok_or(AdmitError::Size)?;
    let arena = a
        .checked_mul(8)
        .and_then(|x| x.checked_add(b))
        .and_then(|x| x.checked_add(c.checked_mul(8)?))
        .and_then(|x| x.checked_add(e.checked_mul(4)?))
        .and_then(|x| x.checked_add(rope))
        .ok_or(AdmitError::Size)?;
    let mut tensor_bytes = 0u64;
    g.for_each_tensor(|t| tensor_bytes = tensor_bytes.saturating_add(u64::try_from(t.data.len()).unwrap_or(u64::MAX)));
    Ok(Manifest {
        payload_bytes: u64::try_from(payload_len).map_err(|_| AdmitError::Size)?,
        arena_bytes: u32::try_from(arena).map_err(|_| AdmitError::Size)?,
        state_bytes_per_session: u32::try_from(state).map_err(|_| AdmitError::Size)?,
        max_sessions: 1,
        max_context: u32::try_from(max_ctx).map_err(|_| AdmitError::Size)?,
        bytes_per_token: tensor_bytes,
        macs_per_run: 0,
        required_features: 0,
    })
}

/// After every segment is verified: open the model and check the manifest, and for a bundle that its tables
/// fit the model. Everything returned borrows the region, which the caller keeps read-only from here on.
pub fn admit<'r>(loader: &Loader, region: &'r [u8]) -> Result<Admitted<'r>, AdmitError> {
    let payload = loader.finish_lm(region).map_err(AdmitError::Container)?;
    let declared = loader.header().manifest;
    let max_ctx = usize::try_from(declared.max_context).map_err(|_| AdmitError::Size)?;
    let bundle = match loader.header().payload_kind {
        kind::GGUF_LM => None,
        kind::LM_BUNDLE => Some(Bundle::open(payload).map_err(AdmitError::Bundle)?),
        _ => return Err(AdmitError::Container(Refusal::Kind)),
    };
    let file = bundle.map_or(payload, |b| b.gguf);
    let truth = manifest(file, payload.len(), max_ctx)?;
    // Features are the signer's statement of what the model was evaluated with; everything else is recomputed.
    if (Manifest { required_features: declared.required_features, ..truth }) != declared {
        return Err(AdmitError::ManifestMismatch);
    }
    let gguf = Gguf::open(file).map_err(AdmitError::Gguf)?;
    let hparams = hparams(&gguf, max_ctx).map_err(AdmitError::Bind)?;
    if let Some(b) = &bundle {
        let d = &hparams.dims;
        let rows = d.max_ctx.checked_mul(d.head_dim / 2).ok_or(AdmitError::Size)?;
        let tok_ok = Tokenizer::new(b.tokenizer).is_ok_and(|t| t.vocab() == d.vocab);
        if b.rope_pairs() != rows || !tok_ok {
            return Err(AdmitError::Tables);
        }
    }
    Ok(Admitted { gguf, hparams, bundle })
}
