// SPDX-License-Identifier: AGPL-3.0-only
//! Step 3 gate: build a signed HNX1 container, stream it in, admit it, run it; and refuse everything doc 06
//! says must be refused, at the step it names.
use neuro_engine::{kernel, pack, Model};
use neuro_hnx::*;

const DEV_SEED: [u8; 32] = [0x42; 32];

struct Dev {
    target: u8,
    features: u32,
    min_svn: u32,
    pk: [u8; 32],
}

impl Platform for Dev {
    fn target(&self) -> u8 {
        self.target
    }
    fn features(&self) -> u32 {
        self.features
    }
    fn engine_abi(&self) -> u16 {
        1
    }
    fn verify(&self, scheme: u8, digest: &[u8; 32], sig: &[u8]) -> bool {
        // Tests use the Ed25519 leg; heqk verifies the hybrid scheme with boot-abi.
        scheme == scheme::ED25519
            && sig.len() == 64
            && ed25519_compact::PublicKey::new(self.pk).verify(digest, &ed25519_compact::Signature::from_slice(sig).unwrap()).is_ok()
    }
    fn licence_allowed(&self, spdx: &[u8]) -> bool {
        matches!(spdx, b"Apache-2.0" | b"MIT" | b"AGPL-3.0-only")
    }
    fn min_svn(&self, _: &[u8; 16]) -> u32 {
        self.min_svn
    }
}

fn dev() -> Dev {
    Dev { target: target::CM5_A76, features: feature::ALL, min_svn: 3, pk: *ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(DEV_SEED)).pk }
}

fn sign_with(seed: [u8; 32]) -> impl FnOnce(&[u8; 32]) -> Option<([u8; MAX_SIG], usize)> {
    move |d| {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
        let mut s = [0u8; MAX_SIG];
        s[..64].copy_from_slice(&*kp.sk.sign(d, None));
        Some((s, 64))
    }
}

/// A 4-bit layer of `rows × cols` as an engine package (the payload).
fn q4_payload(rows: usize, cols: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut w: Vec<u8> = (0..rows * cols / 2).map(|_| next() as u8).collect();
    let b_off = w.len() as u32;
    for _ in 0..rows {
        w.extend_from_slice(&((next() as i32) >> 12).to_le_bytes());
    }
    for _ in 0..rows {
        w.extend_from_slice(&(1 + (next() % 2048) as i32).to_le_bytes());
    }
    let steps = [pack::StepDef { kernel: kernel::GEMV_Q4_I8, shift: 12, input: 0, output: 1, rows: rows as u16, cols: cols as u16, w_off: 0, b_off, mult: 0, zero: 0 }];
    let mut out = vec![0u8; w.len() + 4096];
    let n = pack::package(&mut out, &[(0, cols as u32), (cols as u32, rows as u32)], &steps, &w, (cols + rows) as u32, 0, 1).unwrap();
    out.truncate(n);
    out
}

fn header_for(payload: &[u8], segment_log2: u8) -> Header {
    let m = Model::admit(payload).unwrap();
    let mut licence = [0u8; 32];
    licence[..10].copy_from_slice(b"Apache-2.0");
    Header {
        target: target::CM5_A76,
        scheme: scheme::ED25519,
        engine_abi: 1,
        segment_log2,
        n_segments: 0,
        model_id: [7; 16],
        model_svn: 3,
        manifest: Manifest {
            payload_bytes: 0,
            arena_bytes: m.arena_bytes() as u32,
            state_bytes_per_session: 0,
            max_sessions: 1,
            max_context: 0,
            bytes_per_token: 0,
            macs_per_run: m.macs(),
            required_features: feature::FPSIMD | feature::DOTPROD,
        },
        licence,
        source_sha256: [1; 32],
        eval_sha256: [2; 32],
        merkle_root: [0; 32],
    }
}

fn build(payload: &[u8], mut h: Header, seed: [u8; 32]) -> (Vec<u8>, Header) {
    let mut prefix = vec![0u8; HEADER_LEN + MAX_SEGMENTS * LEAF_LEN + 2 + MAX_SIG];
    let n = build_prefix(&mut h, payload, &mut prefix, sign_with(seed)).unwrap();
    prefix.truncate(n);
    (prefix, h)
}

/// Load the whole thing in the given segment order; return the region.
fn load(prefix: &[u8], payload: &[u8], order: &[u32]) -> Result<Vec<u8>, Refusal> {
    let d = dev();
    let mut l = Loader::open(prefix, &d)?;
    let man = *l.manifest();
    let mut region = vec![0u8; man.payload_bytes as usize];
    let size = l.header().segment_size();
    for &i in order {
        let s = i as usize * size;
        let e = (s + size).min(payload.len());
        if let Err(r) = l.feed(i, &payload[s..e], &mut region) {
            l.abort(&mut region);
            assert!(region.iter().all(|&b| b == 0), "aborted region must be wiped");
            return Err(r);
        }
    }
    l.finish(&region)?;
    Ok(region)
}

#[test]
fn rfc6962_vectors() {
    // Empty-free trees: one leaf = its leaf hash; two leaves = H(1‖l0‖l1); three = H(1‖H(1‖l0‖l1)‖l2).
    let l: Vec<[u8; 32]> = [b"a".as_slice(), b"b", b"c"].iter().map(|d| leaf_hash(d)).collect();
    use sha2::{Digest, Sha256};
    let node = |a: &[u8; 32], b: &[u8; 32]| -> [u8; 32] { Sha256::new().chain_update([1u8]).chain_update(a).chain_update(b).finalize().into() };
    assert_eq!(merkle_root(l[..1].iter().copied()), Some(l[0]));
    assert_eq!(merkle_root(l[..2].iter().copied()), Some(node(&l[0], &l[1])));
    assert_eq!(merkle_root(l.iter().copied()), Some(node(&node(&l[0], &l[1]), &l[2])));
    // Five leaves: split at 4 (largest power of two below 5).
    let l5: Vec<[u8; 32]> = (0..5u8).map(|i| leaf_hash(&[i])).collect();
    let left = node(&node(&l5[0], &l5[1]), &node(&l5[2], &l5[3]));
    assert_eq!(merkle_root(l5.iter().copied()), Some(node(&left, &l5[4])));
    assert_eq!(merkle_root(core::iter::empty()), None);
}

#[test]
fn stream_admit_and_run_a_multi_segment_model() {
    // 512 × 2048 Q4 layer ≈ 524 KiB of weights → 129 segments of 4 KiB.
    let payload = q4_payload(512, 2048, 11);
    let (prefix, h) = build(&payload, header_for(&payload, 12), DEV_SEED);
    let n = h.n_segments;
    println!("payload {} bytes, {} segments of {} bytes, prefix {} bytes", payload.len(), n, h.segment_size(), prefix.len());
    assert!(n > 100);
    // In order, and in a scrambled order (partial loading later needs any order).
    let fwd: Vec<u32> = (0..n).collect();
    let mut scr: Vec<u32> = (0..n).collect();
    scr.reverse();
    scr.swap(3, 40);
    let t = std::time::Instant::now();
    let r1 = load(&prefix, &payload, &fwd).unwrap();
    println!("host load + verify + admit: {:.1} ms (x86, not CM5)", t.elapsed().as_secs_f64() * 1e3);
    let r2 = load(&prefix, &payload, &scr).unwrap();
    assert_eq!(r1, payload);
    assert_eq!(r2, payload);
    // The loaded model runs and equals the payload admitted directly.
    let m = Model::admit(&r1).unwrap();
    let direct = Model::admit(&payload).unwrap();
    let x: Vec<u8> = (0..2048).map(|i| (i * 37) as u8).collect();
    let (mut a1, mut a2) = (vec![0u8; m.arena_bytes()], vec![0u8; m.arena_bytes()]);
    let (mut o1, mut o2) = (vec![0u8; 512], vec![0u8; 512]);
    m.run(&mut a1, &x, &mut o1).unwrap();
    direct.run(&mut a2, &x, &mut o2).unwrap();
    assert_eq!(o1, o2);
    assert_eq!(m.root(), direct.root());
}

#[test]
fn every_refusal_at_its_step() {
    let payload = q4_payload(64, 256, 5);
    let base = header_for(&payload, 12);
    let (prefix, h) = build(&payload, base, DEV_SEED);
    let all: Vec<u32> = (0..h.n_segments).collect();
    assert!(load(&prefix, &payload, &all).is_ok());
    let d = dev();
    let open = |p: &[u8], d: &Dev| Loader::open(p, d).err();

    // Step 1: header policy.
    let with = |f: &dyn Fn(&mut Header)| {
        let mut hh = base;
        f(&mut hh);
        build(&payload, hh, DEV_SEED).0
    };
    assert_eq!(open(&with(&|h| h.target = target::AARCH64_NEON), &d), Some(Refusal::Target));
    assert_eq!(open(&with(&|h| h.target = target::GENERIC_INT), &d), None, "generic packages run anywhere");
    assert_eq!(open(&prefix, &Dev { features: feature::DOTPROD, ..dev() }), Some(Refusal::Features), "no FP/SIMD grant (KR-1), no SIMD package");
    assert_eq!(open(&with(&|h| h.engine_abi = 2), &d), Some(Refusal::EngineAbi));
    assert_eq!(open(&with(&|h| h.licence = { let mut l = [0; 32]; l[..14].copy_from_slice(b"CC-BY-NC-4.0\0\0"); l }), &d), Some(Refusal::Licence));
    assert_eq!(open(&with(&|h| h.eval_sha256 = [0; 32]), &d), Some(Refusal::NoEvalReport));
    assert_eq!(open(&with(&|h| h.model_svn = 2), &d), Some(Refusal::Rollback));
    // Step 1: structure. Every header byte matters: flipping any one is refused (by its field check, the
    // reserved-bytes check, the Merkle root or the signature).
    for i in 0..HEADER_LEN {
        let mut p = prefix.clone();
        p[i] ^= 0x01;
        assert!(Loader::open(&p, &d).is_err(), "header byte {i} change was accepted");
    }
    // Table: a changed leaf no longer hashes to the root.
    let mut p = prefix.clone();
    p[HEADER_LEN + 5] ^= 1;
    assert_eq!(open(&p, &d), Some(Refusal::MerkleRoot));
    // Step 2: signature by another key, and a truncated signature.
    assert_eq!(open(&build(&payload, base, [0x43; 32]).0, &d), Some(Refusal::Signature));
    let mut p = prefix.clone();
    p.truncate(p.len() - 1);
    assert!(open(&p, &d).is_some());
    let mut p = prefix.clone();
    p.push(0);
    assert_eq!(open(&p, &d), Some(Refusal::Length));

    // Step 4: streaming.
    let mut l = Loader::open(&prefix, &d).unwrap();
    let mut region = vec![0u8; l.manifest().payload_bytes as usize];
    let size = l.header().segment_size();
    let seg = |i: usize| &payload[i * size..(i * size + size).min(payload.len())];
    assert_eq!(l.feed(0, &payload[..size], &mut vec![0u8; 10]), Err(Refusal::Region));
    l.feed(0, &payload[..size], &mut region).unwrap();
    assert_eq!(l.feed(0, &payload[..size], &mut region), Err(Refusal::Duplicate));
    assert_eq!(l.feed(9999, &payload[..size], &mut region), Err(Refusal::BadIndex));
    assert_eq!(l.finish(&region).err(), Some(Refusal::Incomplete));
    let mut bad = seg(1).to_vec();
    bad[100] ^= 1;
    assert_eq!(l.feed(1, &bad, &mut region), Err(Refusal::SegmentHash(1)));
    assert_eq!(l.feed(2, seg(2), &mut region), Err(Refusal::Failed), "a failed load stays failed");
    // A short segment where a full one belongs is a hash failure, not a partial write.
    let mut l2 = Loader::open(&prefix, &d).unwrap();
    assert_eq!(l2.feed(0, &payload[..size - 1], &mut region), Err(Refusal::SegmentHash(0)));
    assert_eq!(l.finish(&region).err(), Some(Refusal::Failed));
    let mut all_but_tamper: Vec<u32> = (0..h.n_segments).collect();
    all_but_tamper.rotate_left(1);
    let mut tampered = payload.clone();
    tampered[size * 2 + 7] ^= 0x80;
    assert_eq!(load(&prefix, &tampered, &all_but_tamper), Err(Refusal::SegmentHash(2)));

    // Step 5: the manifest must tell the truth. A package that under-declares its arena or its work to
    // admission is refused, even though it is correctly signed and every segment verifies.
    for lie in [
        |h: &mut Header| h.manifest.arena_bytes -= 1,
        |h: &mut Header| h.manifest.macs_per_run /= 2,
    ] {
        let mut hh = base;
        lie(&mut hh);
        let (p, _) = build(&payload, hh, DEV_SEED);
        assert_eq!(load(&p, &payload, &all), Err(Refusal::ManifestMismatch));
    }
    // A signed, verified payload that is not an admissible engine package.
    let mut junk = payload.clone();
    junk[0] = b'X';
    let (p, _) = build(&junk, base, DEV_SEED);
    assert!(matches!(load(&p, &junk, &all), Err(Refusal::Engine(_))));
}

#[test]
fn fuzzed_prefixes_and_segments_never_panic() {
    let payload = q4_payload(32, 128, 9);
    let (prefix, h) = build(&payload, header_for(&payload, 12), DEV_SEED);
    let d = dev();
    let mut x: u64 = 0xdead_beef;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let iters: usize = std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let mut opened = 0;
    for _ in 0..iters {
        let mut p = prefix.clone();
        for _ in 0..=next() % 3 {
            let i = (next() as usize) % p.len();
            p[i] ^= 1 << (next() % 8);
        }
        if next() % 4 == 0 {
            p.truncate((next() as usize) % p.len());
        }
        let _ = Header::decode(&p);
        if let Ok(mut l) = Loader::open(&p, &d) {
            assert_eq!(p, prefix, "a prefix that differs in any byte must never open");
            opened += 1;
            let mut region = vec![0u8; l.manifest().payload_bytes as usize];
            for i in 0..h.n_segments + 2 {
                let mut seg = payload.get(i as usize * 4096..((i as usize + 1) * 4096).min(payload.len())).unwrap_or(&[]).to_vec();
                if next() % 2 == 0 && !seg.is_empty() {
                    let j = (next() as usize) % seg.len();
                    seg[j] ^= 1;
                }
                let _ = l.feed(i, &seg, &mut region);
            }
            let _ = l.finish(&region);
        }
    }
    println!("fuzz: {iters} mutation attempts; every changed prefix refused; {opened} were byte-identical after mutation (a bit flipped twice) and opened");
}

#[test]
fn which_single_bit_flips_still_open() {
    let payload = q4_payload(32, 128, 9);
    let (prefix, _) = build(&payload, header_for(&payload, 12), DEV_SEED);
    let d = dev();
    let mut hits = vec![];
    for i in 0..prefix.len() {
        for bit in 0..8 {
            let mut p = prefix.clone();
            p[i] ^= 1 << bit;
            if Loader::open(&p, &d).is_ok() {
                hits.push((i, bit));
            }
        }
    }
    println!("prefix {} bytes, {} single-bit flips tried, {} opened", prefix.len(), prefix.len() * 8, hits.len());
    assert!(hits.is_empty(), "{hits:?}");
}
