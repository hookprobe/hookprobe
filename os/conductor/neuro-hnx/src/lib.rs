// SPDX-License-Identifier: AGPL-3.0-only
//! HNX1: the model container and its streaming loader (Neuro doc 06).
//!
//! ```text
//! [ header 256 B ][ segment table: n × 32 B leaf hashes ][ sig_len u16 ][ signature ][ segment 0 ][ segment 1 ] …
//! ```
//!
//! The header carries the identity, target, required CPU features, the resource manifest admission reads,
//! provenance and licence, and the Merkle root (RFC 6962) over the segment hashes. The signature covers
//! `SHA-256(TAG ‖ header)`, so it covers the root, so it covers every segment.
//!
//! The payload (the segments, concatenated) is a `neuro-engine` model package: plan + weights. It contains
//! no code (doc 06 §2).
//!
//! Load order, exactly doc 06 §4:
//! 1. [`Loader::open`]: parse the header, the table and the signature slot; refuse an unknown version,
//!    target, feature, licence, model rollback, a missing eval report; check the table against the root.
//! 2. The platform verifies the signature over [`Loader::signed_digest`] ([`Platform::verify`]).
//! 3. [`Loader::manifest`] goes to admission (ADR 0061 D4): reserve exactly `payload_bytes`, or refuse.
//! 4. [`Loader::feed`] streams each segment into the reserved region, hashing it against its leaf
//!    ([`Loader::accept_in_place`] when the driver read it straight into the region: no staging copy); any
//!    order (partial loading later: MoE experts), each exactly once. A mismatch fails the load and
//!    [`Loader::abort`] wipes the region.
//! 5. [`Loader::finish`] admits the payload in the engine and checks the manifest told the truth (the
//!    engine's own arena and MAC count must equal what admission reserved for).
//! 6. The caller maps the region read-only; [`neuro_engine::Model`] only ever borrows it immutably.
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use neuro_engine::Model;
use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 4] = *b"HNX1";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 256;
pub const LEAF_LEN: usize = 32;
/// Domain tag of the signed digest: a signature made for anything else can never admit a model.
pub const TAG: &[u8] = b"hookprobe/neuro/hnx1/v1\0";
pub const MAX_SEGMENTS: usize = 16 * 1024;
pub const MIN_SEGMENT_LOG2: u8 = 12; // 4 KiB
pub const MAX_SEGMENT_LOG2: u8 = 21; // 2 MiB (one AArch64 block mapping)
pub const MAX_SIG: usize = 8192;
pub const MAX_PAYLOAD: u64 = 1 << 30;
/// The largest language-model payload: 8 GiB (the segment table allows 32 GiB at 2 MiB segments).
pub const MAX_LM_PAYLOAD: u64 = 8 << 30;

/// What the payload is. One container and one loader for every model the device runs.
pub mod kind {
    /// A `neuro-engine` package (plan + weights): the specialists. [`crate::Loader::finish`] admits it.
    pub const ENGINE: u8 = 0;
    /// A GGUF file of a language model the integer engine binds (`neuro-gguf`). [`crate::Loader::finish_lm`]
    /// hands back the verified bytes; the binder checks the manifest against the file.
    pub const GGUF_LM: u8 = 1;
}

/// Targets (doc 06 §3). `GENERIC_INT` runs on any integer-only engine; the others need their features.
pub mod target {
    pub const GENERIC_INT: u8 = 0;
    pub const CM5_A76: u8 = 1;
    pub const AARCH64_NEON: u8 = 2;
    pub const QEMU_VIRT: u8 = 3;
}

/// CPU features a package may require.
pub mod feature {
    /// FP/SIMD enabled for the engine's server (heqk: the KR-1 grant).
    pub const FPSIMD: u32 = 1 << 0;
    /// AArch64 DotProd (SDOT/UDOT).
    pub const DOTPROD: u32 = 1 << 1;
    pub const ALL: u32 = FPSIMD | DOTPROD;
}

/// Signature schemes. heqk's image and artifact trust root is the hybrid one.
pub mod scheme {
    pub const ED25519: u8 = 1;
    pub const HYBRID_ED25519_SLHDSA128S: u8 = 2;
}

/// What admission reserves for, read from the header before any weight byte is loaded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub payload_bytes: u64,
    pub arena_bytes: u32,
    pub state_bytes_per_session: u32,
    pub max_sessions: u16,
    pub max_context: u32,
    /// Weight and state bytes read per generated token (bandwidth pacing, Neuro P4); 0 for specialists.
    pub bytes_per_token: u64,
    pub macs_per_run: u64,
    pub required_features: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub target: u8,
    pub scheme: u8,
    pub engine_abi: u16,
    pub segment_log2: u8,
    pub n_segments: u32,
    pub model_id: [u8; 16],
    pub model_svn: u32,
    pub manifest: Manifest,
    /// SPDX licence id of the WEIGHTS (ASCII, zero-padded).
    pub licence: [u8; 32],
    pub source_sha256: [u8; 32],
    /// Hash of the evaluation report the package passed. Zero = never evaluated = not admissible.
    pub eval_sha256: [u8; 32],
    pub merkle_root: [u8; 32],
    /// One of [`kind`]. Byte 208, which earlier files leave zero: they are engine packages.
    pub payload_kind: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Length,
    Magic,
    Version,
    Reserved,
    /// An unknown payload kind, or a `finish` for another kind than the file's.
    Kind,
    Target,
    Features,
    EngineAbi,
    Segments,
    Payload,
    Licence,
    NoEvalReport,
    Rollback,
    /// The segment table does not hash to the root in the header.
    MerkleRoot,
    Scheme,
    Signature,
    /// The reserved region is not the size the manifest asked for.
    Region,
    BadIndex,
    Duplicate,
    /// A segment's bytes do not hash to its leaf: the load is aborted.
    SegmentHash(u32),
    Incomplete,
    /// The payload is not an admissible engine package.
    Engine(neuro_engine::Refusal),
    /// The manifest did not tell the truth about the payload (arena or work).
    ManifestMismatch,
    Failed,
}

/// What the device provides: its identity as a target, its trust root, its policy.
pub trait Platform {
    fn target(&self) -> u8;
    fn features(&self) -> u32;
    fn engine_abi(&self) -> u16;
    /// Verify `sig` over `digest` under the model-signing trust root for `scheme`.
    fn verify(&self, scheme: u8, digest: &[u8; 32], sig: &[u8]) -> bool;
    /// May weights under this SPDX licence run here?
    fn licence_allowed(&self, spdx: &[u8]) -> bool;
    /// The lowest SVN still accepted for this model id (rollback floor).
    fn min_svn(&self, model_id: &[u8; 16]) -> u32;
}

// ------------------------------------------------------------------ RFC 6962 Merkle tree

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// RFC 6962 Merkle Tree Hash over leaf hashes, without allocation: perfect subtrees are folded on a stack
/// as leaves arrive, then combined right to left, which is exactly the RFC's "largest power of two" split.
pub fn merkle_root(leaves: impl Iterator<Item = [u8; 32]>) -> Option<[u8; 32]> {
    let mut stack: [([u8; 32], u32); 32] = [([0; 32], 0); 32];
    let mut top = 0usize;
    for leaf in leaves {
        let mut cur = (leaf, 0u32);
        while top > 0 {
            let prev = *stack.get(top.checked_sub(1)?)?;
            if prev.1 != cur.1 {
                break;
            }
            cur = (node_hash(&prev.0, &cur.0), cur.1.checked_add(1)?);
            top = top.checked_sub(1)?;
        }
        *stack.get_mut(top)? = cur;
        top = top.checked_add(1)?;
    }
    let mut acc = stack.get(top.checked_sub(1)?)?.0;
    let mut i = top.checked_sub(1)?;
    while i > 0 {
        i = i.checked_sub(1)?;
        acc = node_hash(&stack.get(i)?.0, &acc);
    }
    Some(acc)
}

// ------------------------------------------------------------------ header

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.arr::<1>()?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.arr()?))
    }
}

impl Header {
    /// Fixed layout, 256 bytes; every unused byte must be zero.
    pub fn decode(b: &[u8]) -> Result<Self, Refusal> {
        let b = b.get(..HEADER_LEN).ok_or(Refusal::Length)?;
        let r = &mut Rd { b, i: 0 };
        let l = Refusal::Length;
        if r.arr::<4>().ok_or(l)? != MAGIC {
            return Err(Refusal::Magic);
        }
        if r.u16().ok_or(l)? != VERSION {
            return Err(Refusal::Version);
        }
        let h = Header {
            target: r.u8().ok_or(l)?,
            scheme: r.u8().ok_or(l)?,
            engine_abi: r.u16().ok_or(l)?,
            segment_log2: r.u8().ok_or(l)?,
            n_segments: {
                let _pad = r.u8().ok_or(l)?;
                r.u32().ok_or(l)?
            },
            model_id: r.arr().ok_or(l)?,
            model_svn: r.u32().ok_or(l)?,
            manifest: Manifest {
                payload_bytes: r.u64().ok_or(l)?,
                arena_bytes: r.u32().ok_or(l)?,
                state_bytes_per_session: r.u32().ok_or(l)?,
                max_sessions: r.u16().ok_or(l)?,
                max_context: {
                    let _pad = r.u16().ok_or(l)?;
                    r.u32().ok_or(l)?
                },
                bytes_per_token: r.u64().ok_or(l)?,
                macs_per_run: r.u64().ok_or(l)?,
                required_features: r.u32().ok_or(l)?,
            },
            licence: r.arr().ok_or(l)?,
            source_sha256: r.arr().ok_or(l)?,
            eval_sha256: r.arr().ok_or(l)?,
            merkle_root: r.arr().ok_or(l)?,
            payload_kind: r.u8().ok_or(l)?,
        };
        if !matches!(h.payload_kind, kind::ENGINE | kind::GGUF_LM) {
            return Err(Refusal::Kind);
        }
        // The pads and the tail are reserved: zero, so no field can hide in them.
        // Layout: segment_log2 @10, pad @11; max_sessions @52..54, pad @54..56; payload_kind @208; reserved tail @209..256.
        let pad_ok = b.get(11) == Some(&0) && b.get(54..56) == Some(&[0, 0]);
        if !pad_ok || r.take(HEADER_LEN.saturating_sub(r.i)).ok_or(l)?.iter().any(|&x| x != 0) {
            return Err(Refusal::Reserved);
        }
        Ok(h)
    }

    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        *out = [0; HEADER_LEN];
        let m = &self.manifest;
        let mut i = 0usize;
        let mut put = |s: &[u8]| {
            let end = i.saturating_add(s.len());
            if let Some(d) = out.get_mut(i..end) {
                d.copy_from_slice(s);
            }
            i = end;
        };
        put(&MAGIC);
        put(&VERSION.to_le_bytes());
        put(&[self.target, self.scheme]);
        put(&self.engine_abi.to_le_bytes());
        put(&[self.segment_log2, 0]);
        put(&self.n_segments.to_le_bytes());
        put(&self.model_id);
        put(&self.model_svn.to_le_bytes());
        put(&m.payload_bytes.to_le_bytes());
        put(&m.arena_bytes.to_le_bytes());
        put(&m.state_bytes_per_session.to_le_bytes());
        put(&m.max_sessions.to_le_bytes());
        put(&[0, 0]);
        put(&m.max_context.to_le_bytes());
        put(&m.bytes_per_token.to_le_bytes());
        put(&m.macs_per_run.to_le_bytes());
        put(&m.required_features.to_le_bytes());
        put(&self.licence);
        put(&self.source_sha256);
        put(&self.eval_sha256);
        put(&self.merkle_root);
        put(&[self.payload_kind]);
    }

    pub fn segment_size(&self) -> usize {
        1usize.checked_shl(u32::from(self.segment_log2)).unwrap_or(0)
    }

    /// Bytes of segment `i` (the last one may be short).
    pub fn segment_len(&self, i: u32) -> Option<usize> {
        let size = self.segment_size();
        let start = usize::try_from(i).ok()?.checked_mul(size)?;
        let total = usize::try_from(self.manifest.payload_bytes).ok()?;
        if start >= total {
            return None;
        }
        Some(size.min(total.checked_sub(start)?))
    }

    /// Bytes before the first segment: header, table, signature length and signature.
    pub fn prefix_len(&self, sig_len: usize) -> Option<usize> {
        HEADER_LEN.checked_add(usize::try_from(self.n_segments).ok()?.checked_mul(LEAF_LEN)?)?.checked_add(2)?.checked_add(sig_len)
    }

    /// The digest the signature covers.
    pub fn signed_digest(&self) -> [u8; 32] {
        let mut b = [0u8; HEADER_LEN];
        self.encode(&mut b);
        let mut h = Sha256::new();
        h.update(TAG);
        h.update(b);
        h.finalize().into()
    }
}

fn licence_str(l: &[u8; 32]) -> &[u8] {
    let n = l.iter().position(|&c| c == 0).unwrap_or(l.len());
    l.get(..n).unwrap_or(&[])
}

// ------------------------------------------------------------------ loader

/// Bitmap of received segments (fixed size; no allocation).
const SEEN_WORDS: usize = MAX_SEGMENTS / 64;

pub struct Loader<'a> {
    header: Header,
    table: &'a [u8],
    seen: [u64; SEEN_WORDS],
    received: u32,
    failed: bool,
}

impl<'a> Loader<'a> {
    /// Steps 1 and 2. `prefix` = the bytes before the first segment (see [`Header::prefix_len`]).
    pub fn open(prefix: &'a [u8], p: &impl Platform) -> Result<Self, Refusal> {
        let h = Header::decode(prefix)?;
        if h.target != p.target() && h.target != target::GENERIC_INT {
            return Err(Refusal::Target);
        }
        let m = &h.manifest;
        if m.required_features & !feature::ALL != 0 || m.required_features & !p.features() != 0 {
            return Err(Refusal::Features);
        }
        if h.engine_abi != p.engine_abi() {
            return Err(Refusal::EngineAbi);
        }
        if !(MIN_SEGMENT_LOG2..=MAX_SEGMENT_LOG2).contains(&h.segment_log2) {
            return Err(Refusal::Segments);
        }
        let cap = if h.payload_kind == kind::GGUF_LM { MAX_LM_PAYLOAD } else { MAX_PAYLOAD };
        if m.payload_bytes == 0 || m.payload_bytes > cap {
            return Err(Refusal::Payload);
        }
        let n = usize::try_from(h.n_segments).map_err(|_| Refusal::Segments)?;
        let size = u64::try_from(h.segment_size()).map_err(|_| Refusal::Segments)?;
        if n == 0 || n > MAX_SEGMENTS || u64::try_from(n).ok() != Some(m.payload_bytes.div_ceil(size)) {
            return Err(Refusal::Segments);
        }
        let lic = licence_str(&h.licence);
        if lic.is_empty() || !p.licence_allowed(lic) {
            return Err(Refusal::Licence);
        }
        if h.eval_sha256 == [0; 32] {
            return Err(Refusal::NoEvalReport);
        }
        if h.model_svn < p.min_svn(&h.model_id) {
            return Err(Refusal::Rollback);
        }
        let table_end = HEADER_LEN.checked_add(n.checked_mul(LEAF_LEN).ok_or(Refusal::Length)?).ok_or(Refusal::Length)?;
        let table = prefix.get(HEADER_LEN..table_end).ok_or(Refusal::Length)?;
        let root = merkle_root(table.as_chunks::<LEAF_LEN>().0.iter().copied()).ok_or(Refusal::MerkleRoot)?;
        if root != h.merkle_root {
            return Err(Refusal::MerkleRoot);
        }
        let sig_len = prefix.get(table_end..table_end.saturating_add(2)).and_then(|b| b.try_into().ok()).map(u16::from_le_bytes).ok_or(Refusal::Length)?;
        let sig_len = usize::from(sig_len);
        if sig_len == 0 || sig_len > MAX_SIG {
            return Err(Refusal::Signature);
        }
        let sig_start = table_end.saturating_add(2);
        let sig = prefix.get(sig_start..sig_start.saturating_add(sig_len)).ok_or(Refusal::Length)?;
        if prefix.len() != sig_start.saturating_add(sig_len) {
            return Err(Refusal::Length);
        }
        if !matches!(h.scheme, scheme::ED25519 | scheme::HYBRID_ED25519_SLHDSA128S) {
            return Err(Refusal::Scheme);
        }
        if !p.verify(h.scheme, &h.signed_digest(), sig) {
            return Err(Refusal::Signature);
        }
        Ok(Self { header: h, table, seen: [0; SEEN_WORDS], received: 0, failed: false })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Step 3: what to reserve. Nothing is loaded before admission says yes.
    pub fn manifest(&self) -> &Manifest {
        &self.header.manifest
    }

    /// Step 4: one segment into the reserved region (exactly `payload_bytes` long).
    pub fn feed(&mut self, index: u32, data: &[u8], region: &mut [u8]) -> Result<(), Refusal> {
        let (start, len) = self.slot(index, region.len())?;
        if data.len() != len || !self.leaf_matches(index, data)? {
            // Fail closed: the whole load is void; the caller wipes the region and releases the grant.
            self.failed = true;
            return Err(Refusal::SegmentHash(index));
        }
        region.get_mut(start..start.saturating_add(len)).ok_or(Refusal::Region)?.copy_from_slice(data);
        self.mark(index)
    }

    /// Step 4 without a staging copy: the storage driver has read segment `index` straight into its place in
    /// the reserved region (for example by DMA), and it is hashed there. Nothing is copied, so the only
    /// memory a load needs beyond the region is this loader.
    ///
    /// Until [`Loader::finish`] the region holds bytes that are not all verified, as it does between calls to
    /// [`Loader::feed`]: it must stay unmapped from the engine until then. A mismatch fails the load, and
    /// [`Loader::abort`] wipes the region.
    pub fn accept_in_place(&mut self, index: u32, region: &[u8]) -> Result<(), Refusal> {
        let (start, len) = self.slot(index, region.len())?;
        let data = region.get(start..start.saturating_add(len)).ok_or(Refusal::Region)?;
        if !self.leaf_matches(index, data)? {
            self.failed = true;
            return Err(Refusal::SegmentHash(index));
        }
        self.mark(index)
    }

    /// Where segment `index` goes in a region of `region_len` bytes, after the checks every segment gets: the
    /// load has not failed, the region is exactly the reserved size, the index exists and was not seen.
    fn slot(&self, index: u32, region_len: usize) -> Result<(usize, usize), Refusal> {
        if self.failed {
            return Err(Refusal::Failed);
        }
        if u64::try_from(region_len).ok() != Some(self.header.manifest.payload_bytes) {
            return Err(Refusal::Region);
        }
        let len = self.header.segment_len(index).ok_or(Refusal::BadIndex)?;
        let (w, bit) = (usize::try_from(index / 64).map_err(|_| Refusal::BadIndex)?, index % 64);
        if self.seen.get(w).ok_or(Refusal::BadIndex)? & (1u64 << bit) != 0 {
            return Err(Refusal::Duplicate);
        }
        let start = usize::try_from(index).map_err(|_| Refusal::BadIndex)?.checked_mul(self.header.segment_size()).ok_or(Refusal::BadIndex)?;
        Ok((start, len))
    }

    fn leaf_matches(&self, index: u32, data: &[u8]) -> Result<bool, Refusal> {
        let leaf_at = usize::try_from(index).map_err(|_| Refusal::BadIndex)?.checked_mul(LEAF_LEN).ok_or(Refusal::BadIndex)?;
        let want = self.table.get(leaf_at..leaf_at.saturating_add(LEAF_LEN)).ok_or(Refusal::BadIndex)?;
        Ok(leaf_hash(data) == want)
    }

    fn mark(&mut self, index: u32) -> Result<(), Refusal> {
        let (w, bit) = (usize::try_from(index / 64).map_err(|_| Refusal::BadIndex)?, index % 64);
        *self.seen.get_mut(w).ok_or(Refusal::BadIndex)? |= 1u64 << bit;
        self.received = self.received.saturating_add(1);
        Ok(())
    }

    /// After a failed load: zero the region so no partial, unverified weights survive.
    pub fn abort(&mut self, region: &mut [u8]) {
        self.failed = true;
        region.fill(0);
    }

    pub fn complete(&self) -> bool {
        !self.failed && self.received == self.header.n_segments
    }

    /// Step 5: every segment present and verified → the engine admits the payload, and the manifest must
    /// equal what the engine computes (a package cannot under-declare its memory or work to admission).
    pub fn finish<'r>(&self, region: &'r [u8]) -> Result<Model<'r>, Refusal> {
        if self.failed {
            return Err(Refusal::Failed);
        }
        if !self.complete() {
            return Err(Refusal::Incomplete);
        }
        if self.header.payload_kind != kind::ENGINE {
            return Err(Refusal::Kind);
        }
        let m = Model::admit(region).map_err(Refusal::Engine)?;
        let man = &self.header.manifest;
        if u64::try_from(m.arena_bytes()).ok() != Some(u64::from(man.arena_bytes)) || m.macs() != man.macs_per_run {
            return Err(Refusal::ManifestMismatch);
        }
        Ok(m)
    }
}

impl Loader<'_> {
    /// Step 5 for a language model ([`kind::GGUF_LM`]): every segment present and verified, so the region
    /// is the signed file, byte for byte. The binder (`neuro_gguf::hnx::admit`) opens it and checks that the
    /// manifest told admission the truth; this crate does not know the model's format.
    pub fn finish_lm<'r>(&self, region: &'r [u8]) -> Result<&'r [u8], Refusal> {
        if self.failed {
            return Err(Refusal::Failed);
        }
        if !self.complete() {
            return Err(Refusal::Incomplete);
        }
        if self.header.payload_kind != kind::GGUF_LM {
            return Err(Refusal::Kind);
        }
        if u64::try_from(region.len()).ok() != Some(self.header.manifest.payload_bytes) {
            return Err(Refusal::Region);
        }
        Ok(region)
    }
}

/// Build side (the container part of `hnx-compile`): fill in the segment hashes and the root, then let the
/// caller sign the digest. Writes `prefix` (header, table, signature) into `out`; segments follow it as the
/// payload itself. Returns the prefix length.
pub fn build_prefix(header: &mut Header, payload: &[u8], out: &mut [u8], sign: impl FnOnce(&[u8; 32]) -> Option<([u8; MAX_SIG], usize)>) -> Option<usize> {
    let size = header.segment_size();
    if size == 0 {
        return None;
    }
    header.manifest.payload_bytes = u64::try_from(payload.len()).ok()?;
    header.n_segments = u32::try_from(payload.len().div_ceil(size)).ok()?;
    let mut table_len = 0usize;
    for (i, seg) in payload.chunks(size).enumerate() {
        let at = HEADER_LEN.checked_add(i.checked_mul(LEAF_LEN)?)?;
        out.get_mut(at..at.checked_add(LEAF_LEN)?)?.copy_from_slice(&leaf_hash(seg));
        table_len = table_len.checked_add(LEAF_LEN)?;
    }
    let table = out.get(HEADER_LEN..HEADER_LEN.checked_add(table_len)?)?;
    header.merkle_root = merkle_root(table.as_chunks::<LEAF_LEN>().0.iter().copied())?;
    let mut hb = [0u8; HEADER_LEN];
    header.encode(&mut hb);
    out.get_mut(..HEADER_LEN)?.copy_from_slice(&hb);
    let (sig, sig_len) = sign(&header.signed_digest())?;
    let at = HEADER_LEN.checked_add(table_len)?;
    out.get_mut(at..at.checked_add(2)?)?.copy_from_slice(&u16::try_from(sig_len).ok()?.to_le_bytes());
    let s = at.checked_add(2)?;
    out.get_mut(s..s.checked_add(sig_len)?)?.copy_from_slice(sig.get(..sig_len)?);
    s.checked_add(sig_len)
}
