// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0060 S2b build-host tool: the signed tiny model, the prompt and the host's answer for `[P-smp-engine]`.
//! Usage: `worker-engine-model <out_dir>`. Writes `model.prefix`, `model.bundle`, `model.pk`, `prompt.bin`,
//! `golden.bin` and `sizes.txt`. Mirrors `os/conductor/conductor-mock/tests/p0_worker.rs` (`admitted`,
//! `the_engine_op_for_a_worker_core`), with a smaller context so it fits a QEMU worker; the answer goes through
//! `conductor_engine_entry::run` (#1666), the safe form of the C entry the worker core calls.
use conductor_core::crypto::{public_key, sign, verify};
use conductor_engine_entry::{arena_need, op, run, Job, Limits, CANCELLED, HEADER};
use conductor_p0::core_job::{status, Link};
use neuro_gguf::hnx::{admit, manifest_for_bundle};
use neuro_hnx::{build_prefix, kind, scheme, target, Header, Loader, Platform, HEADER_LEN, LEAF_LEN, MAX_SIG};
use neuro_kernels::Simd;
use std::sync::atomic::{AtomicBool, AtomicU32};

/// Context of the gate's model: prompt (bytes are tokens) plus answer must fit.
pub const CTX: usize = 2048;
pub const MAX_ANSWER: usize = 1600;
pub const SEED: u64 = 7;
/// Test signing seed: QEMU gate only, never a release key.
const SIGN_SEED: [u8; 32] = [0x77; 32];
pub const TAG: &[u8] = b"test/hnx";

struct Node;
impl Platform for Node {
    fn target(&self) -> u8 {
        target::QEMU_VIRT
    }
    fn features(&self) -> u32 {
        0
    }
    fn engine_abi(&self) -> u16 {
        1
    }
    fn verify(&self, s: u8, digest: &[u8; 32], sig: &[u8]) -> bool {
        s == scheme::ED25519 && sig.try_into().is_ok_and(|sig: &[u8; 64]| verify(&public_key(&SIGN_SEED), TAG, digest, sig))
    }
    fn licence_allowed(&self, spdx: &[u8]) -> bool {
        spdx == b"AGPL-3.0-only"
    }
    fn min_svn(&self, _: &[u8; 16]) -> u32 {
        1
    }
}

fn tokens() -> Vec<Vec<u8>> {
    let mut t: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
    t.push(b"<|im_end|>".to_vec());
    t
}

fn gguf_tokens() -> Vec<Vec<u8>> {
    let mut t: Vec<Vec<u8>> = (0..=255u8).map(|b| char::from(b).to_string().into_bytes()).collect();
    t.push(b"<|im_end|>".to_vec());
    t
}

fn main() {
    let out = std::env::args().nth(1).expect("usage: worker-engine-model <out_dir>");
    let out = std::path::Path::new(&out);

    // The signed bundle, exactly as the Conductor's test builds it (seeded weights: the answer depends on arithmetic).
    let file = tok_build::tiny_qwen3_gguf_seeded(&gguf_tokens(), CTX as u32, SEED);
    let tok = tok_build::blob(&tok_build::Source { tokens: tokens(), merges: vec![], added: vec![256] }, &tok_build::unicode_ranges(), &tok_build::nfc_tables()).unwrap();
    let rope: Vec<u8> = (0..CTX * 16)
        .flat_map(|i| if i % 3 == 0 { [0i32.to_le_bytes(), (1i32 << 30).to_le_bytes()].concat() } else { [(1i32 << 30).to_le_bytes(), 0i32.to_le_bytes()].concat() })
        .collect();
    let bundle: Vec<u8> = tok_build::bundle([&file, &tok, &rope, &[]]).unwrap();
    let mut licence = [0u8; 32];
    licence[..13].copy_from_slice(b"AGPL-3.0-only");
    let mut h = Header {
        target: target::QEMU_VIRT,
        scheme: scheme::ED25519,
        engine_abi: 1,
        segment_log2: 16,
        n_segments: 0,
        model_id: [9; 16],
        model_svn: 1,
        manifest: manifest_for_bundle(&bundle, CTX).unwrap(),
        licence,
        source_sha256: [1; 32],
        eval_sha256: [2; 32],
        merkle_root: [0; 32],
        payload_kind: kind::LM_BUNDLE,
    };
    let mut prefix = vec![0u8; HEADER_LEN + bundle.len().div_ceil(1 << 16) * LEAF_LEN + 2 + 64];
    let n = build_prefix(&mut h, &bundle, &mut prefix, |d| {
        let mut o = [0u8; MAX_SIG];
        o[..64].copy_from_slice(&sign(&SIGN_SEED, TAG, d)?);
        Some((o, 64))
    })
    .unwrap();
    prefix.truncate(n);

    // Load and admit it on this host, the way the worker engine will.
    let mut l = Loader::open(&prefix, &Node).unwrap();
    let mut region = vec![0u8; bundle.len()];
    for i in 0..bundle.len().div_ceil(1 << 16) {
        let (s, e) = (i * 65536, ((i + 1) * 65536).min(bundle.len()));
        region[s..e].copy_from_slice(&bundle[s..e]);
        l.accept_in_place(i as u32, &mut region).unwrap();
    }
    admit(&l, &region).unwrap();

    // Answer through the Conductor's own entry (conductor_engine_entry::run, the safe form of the C entry the
    // worker calls), with scalar kernels on this host: the same code path the worker core runs.
    let limits = Limits { max_ctx: CTX as u32, max_answer: MAX_ANSWER as u32 };
    let need = arena_need(&region, limits).unwrap();
    let mut arena = vec![0u8; need as usize];
    let prompt = format!("{}F1 H1->R1:443 n=3 bytes=1200\nF2 H2->R1:22 n=1 bytes=90{}Assess this window.", neuro_contract::USER_HEAD, neuro_contract::USER_MID);
    let (progress, cancel) = (AtomicU32::new(0), AtomicBool::new(false));
    let mut result = vec![0u8; HEADER + MAX_ANSWER * 4];
    let (st, value) = run(Job {
        model: &region,
        arena: &mut arena,
        limits,
        simd: Simd::SCALAR,
        op: op::ENGINE_INFER,
        a: 0,
        b: prompt.len() as u64,
        link: Link { window: prompt.as_bytes(), progress: &progress, cancel: &cancel },
        result: &mut result,
    });
    assert_eq!(st, status::OK, "the host could not answer: {st:#x}");
    let golden = &result[HEADER..HEADER + value as usize];
    let tokens = u32::from_le_bytes(result[0..4].try_into().unwrap());

    std::fs::write(out.join("model.prefix"), &prefix).unwrap();
    std::fs::write(out.join("model.bundle"), &bundle).unwrap();
    // ADR 0061 M1 gate: the same signed model as one container a loader places in RAM above 4 GiB:
    // header (64 B: "HQMODEL1", prefix off/len, bundle off/len, total), prefix at 4 KiB, bundle page-aligned.
    let page_up = |n: usize| (n + 4095) & !4095;
    let (p_off, b_off) = (4096usize, page_up(4096 + prefix.len()));
    let total = b_off + bundle.len();
    let mut c = vec![0u8; total];
    c[..8].copy_from_slice(b"HQMODEL1");
    for (i, v) in [p_off, prefix.len(), b_off, bundle.len(), total].iter().enumerate() {
        c[8 + i * 8..16 + i * 8].copy_from_slice(&(*v as u64).to_le_bytes());
    }
    c[p_off..p_off + prefix.len()].copy_from_slice(&prefix);
    c[b_off..].copy_from_slice(&bundle);
    std::fs::write(out.join("model.container"), &c).unwrap();
    std::fs::write(out.join("model.pk"), public_key(&SIGN_SEED)).unwrap();
    std::fs::write(out.join("prompt.bin"), prompt.as_bytes()).unwrap();
    std::fs::write(out.join("golden.bin"), golden).unwrap();
    std::fs::write(out.join("status_cancelled.bin"), CANCELLED.to_le_bytes()).unwrap();
    std::fs::write(out.join("sizes.txt"), format!("bundle {} prefix {} arena_need {} answer {} tokens {}\n", bundle.len(), prefix.len(), need, value, tokens)).unwrap();
}
