// SPDX-License-Identifier: AGPL-3.0-only
//! neuro-engine N0 gate: (1) the frozen S1 specialist, shipped as a DATA package, gives bit-identical
//! scores and alerts to `neuro_l1`'s compiled-in code; (2) random multi-layer models match an independently
//! written reference; (3) every malformed package is refused for the right reason; (4) fuzzed packages never
//! panic; (5) stepping equals running.
use neuro_engine::*;
use sha2::{Digest, Sha256};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

#[derive(Clone, Copy)]
struct St {
    kernel: u8,
    shift: u8,
    input: u16,
    output: u16,
    rows: u16,
    cols: u16,
    w_off: u32,
    b_off: u32,
    mult: i32,
    zero: i32,
}

/// The build-host packer (the first piece of `hnx-compile`). Lays out header, memory plan, plan, weights, root.
fn pack(slots: &[(u32, u32)], steps: &[St], weights: &[u8], arena: u32, in_slot: u16, out_slot: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&MAGIC);
    p.extend_from_slice(&VERSION.to_le_bytes());
    p.push(ARCH_SPECIALIST);
    p.push(TARGET_GENERIC_INT);
    p.extend_from_slice(&(slots.len() as u16).to_le_bytes());
    p.extend_from_slice(&(steps.len() as u16).to_le_bytes());
    p.extend_from_slice(&arena.to_le_bytes());
    p.extend_from_slice(&(weights.len() as u32).to_le_bytes());
    p.extend_from_slice(&in_slot.to_le_bytes());
    p.extend_from_slice(&out_slot.to_le_bytes());
    p.extend_from_slice(&[0; 8]);
    for (o, l) in slots {
        p.extend_from_slice(&o.to_le_bytes());
        p.extend_from_slice(&l.to_le_bytes());
    }
    for s in steps {
        p.push(s.kernel);
        p.push(s.shift);
        for v in [s.input, s.output, s.rows, s.cols, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&s.w_off.to_le_bytes());
        p.extend_from_slice(&s.b_off.to_le_bytes());
        p.extend_from_slice(&s.mult.to_le_bytes());
        p.extend_from_slice(&s.zero.to_le_bytes());
    }
    p.extend_from_slice(weights);
    reseal(&mut p);
    p
}

fn reseal(p: &mut Vec<u8>) {
    if p.len() >= HEADER_LEN + ROOT_LEN && p.len() - ROOT_LEN >= HEADER_LEN {
        // (only called on freshly built or deliberately altered bodies)
    }
    let d: [u8; 32] = Sha256::digest(&p[..]).into();
    p.extend_from_slice(&d);
}

fn rehash(p: &mut Vec<u8>) {
    let n = p.len() - ROOT_LEN;
    p.truncate(n);
    reseal(p);
}

const NONE: St = St { kernel: 0, shift: 0, input: 0, output: 0, rows: 0, cols: 0, w_off: 0, b_off: 0, mult: 0, zero: 0 };

/// S1 as a package: 28 u8 features → i32 score → alert bit. Output slot = score ‖ alert (5 bytes).
fn s1_package() -> Vec<u8> {
    use neuro_l1::s1_model::{BQ, THR_Q, WQ};
    let mut w = Vec::new();
    for v in WQ {
        w.extend_from_slice(&v.to_le_bytes());
    }
    let b_off = w.len() as u32;
    w.extend_from_slice(&BQ.to_le_bytes());
    // slots: 0 input[0..28], 1 score[28..32], 2 alert[32..33], 3 result = score ‖ alert [28..33]
    let slots = [(0, 28), (28, 4), (32, 1), (28, 5)];
    let steps = [
        St { kernel: kernel::AFFINE_U8_I16, input: 0, output: 1, rows: 1, cols: 28, w_off: 0, b_off, ..NONE },
        St { kernel: kernel::GT_I32, input: 1, output: 2, zero: THR_Q, ..NONE },
    ];
    pack(&slots, &steps, &w, 33, 0, 3)
}

#[test]
fn s1_as_data_equals_s1_as_code() {
    let pkg = s1_package();
    let m = Model::admit(&pkg).expect("S1 package admits");
    assert_eq!((m.input_len(), m.output_len(), m.steps(), m.macs(), m.arena_bytes()), (28, 5, 2, 28, 33));
    println!("S1 package: {} bytes, arena {} bytes, {} MACs per run", pkg.len(), m.arena_bytes(), m.macs());
    let mut arena = [0u8; 33];
    let mut rng = Rng(0x5151_5151);
    let mut alerts = 0;
    let mut check = |q: [u8; 28], arena: &mut [u8; 33]| {
        let mut out = [0u8; 5];
        m.run(arena, &q, &mut out).unwrap();
        let score = i32::from_le_bytes(out[..4].try_into().unwrap());
        assert_eq!(score, neuro_l1::score(&q), "score differs for {q:?}");
        assert_eq!(out[4] == 1, neuro_l1::alert(&q), "alert differs for {q:?}");
        out[4]
    };
    for q in [[0u8; 28], [255u8; 28], [128u8; 28]] {
        check(q, &mut arena);
    }
    for _ in 0..200_000 {
        let mut q = [0u8; 28];
        for v in &mut q {
            *v = rng.next() as u8;
        }
        alerts += check(q, &mut arena) as u32;
    }
    assert!(alerts > 0 && alerts < 200_000, "both outcomes exercised ({alerts})");
}

/// Independent reference: plain i128 arithmetic over explicit tensors, no shared code with the engine.
fn ref_mlp(layers: &[(Vec<Vec<i8>>, Vec<i32>, i32, u8, i32, bool)], x: &[i8]) -> (Vec<i8>, u8) {
    let mut v: Vec<i128> = x.iter().map(|&a| a as i128).collect();
    for (w, b, mult, shift, zero, relu) in layers {
        let mut next = vec![];
        for (row, bias) in w.iter().zip(b) {
            let acc: i128 = row.iter().zip(&v).map(|(&a, &c)| a as i128 * c).sum::<i128>() + *bias as i128;
            let round = if *shift == 0 { 0 } else { 1i128 << (shift - 1) };
            let mut y = ((acc * *mult as i128 + round) >> shift) + *zero as i128;
            y = y.clamp(-128, 127);
            if *relu && y < 0 {
                y = 0;
            }
            next.push(y);
        }
        v = next;
    }
    let out: Vec<i8> = v.iter().map(|&a| a as i8).collect();
    let mut best = 0;
    for (i, &a) in out.iter().enumerate() {
        if a > out[best] {
            best = i;
        }
    }
    (out, best as u8)
}

#[test]
fn random_models_match_the_reference_and_stepping_equals_running() {
    let mut rng = Rng(0xfeed_beef);
    for case in 0..300 {
        let n_layers = 1 + rng.below(3) as usize;
        let mut dims = vec![1 + rng.below(40) as usize];
        for _ in 0..n_layers {
            dims.push(1 + rng.below(24) as usize);
        }
        let (mut slots, mut steps, mut weights, mut layers) = (vec![], vec![], vec![], vec![]);
        let mut off = 0u32;
        for d in &dims {
            slots.push((off, *d as u32));
            off += *d as u32;
        }
        for l in 0..n_layers {
            let (cols, rows) = (dims[l], dims[l + 1]);
            let w: Vec<Vec<i8>> = (0..rows).map(|_| (0..cols).map(|_| rng.next() as i8).collect()).collect();
            let b: Vec<i32> = (0..rows).map(|_| (rng.next() as i32) >> 12).collect();
            let (mult, shift, zero, relu) = (1 + rng.below(1 << 14) as i32, rng.below(24) as u8, rng.below(21) as i32 - 10, rng.below(2) == 0);
            let w_off = weights.len() as u32;
            for row in &w {
                weights.extend(row.iter().map(|&a| a as u8));
            }
            let b_off = weights.len() as u32;
            for v in &b {
                weights.extend_from_slice(&v.to_le_bytes());
            }
            steps.push(St { kernel: kernel::DENSE_I8, shift, input: l as u16, output: l as u16 + 1, rows: rows as u16, cols: cols as u16, w_off, b_off, mult, zero });
            if relu {
                steps.push(St { kernel: kernel::RELU_I8, input: l as u16 + 1, output: l as u16 + 1, ..NONE });
            }
            layers.push((w, b, mult, shift, zero, relu));
        }
        // result slot: last layer output followed by the argmax byte
        let last = *dims.last().unwrap() as u32;
        slots.push((off, 1));
        steps.push(St { kernel: kernel::ARGMAX_I8, input: n_layers as u16, output: n_layers as u16 + 1, ..NONE });
        slots.push((off - last, last + 1));
        let pkg = pack(&slots, &steps, &weights, off + 1, 0, n_layers as u16 + 2);
        let m = Model::admit(&pkg).unwrap_or_else(|e| panic!("case {case}: {e:?}"));
        let mut arena = vec![0u8; m.arena_bytes()];
        for _ in 0..20 {
            let x: Vec<i8> = (0..dims[0]).map(|_| rng.next() as i8).collect();
            let xb: Vec<u8> = x.iter().map(|&a| a as u8).collect();
            let mut out = vec![0u8; m.output_len()];
            m.run(&mut arena, &xb, &mut out).unwrap();
            let (want, arg) = ref_mlp(&layers, &x);
            assert_eq!(&out[..want.len()], &want.iter().map(|&a| a as u8).collect::<Vec<_>>()[..], "case {case}");
            assert_eq!(out[want.len()], arg, "case {case} argmax");
            // Interruptible: one step at a time, with the arena untouched in between, gives the same bytes.
            let mut a2 = vec![0xAAu8; m.arena_bytes()];
            let mut c = m.begin(&mut a2, &xb).unwrap();
            let mut n = 1;
            while m.step(&mut a2, &mut c).unwrap() {
                n += 1;
            }
            assert_eq!(n, m.steps());
            let mut out2 = vec![0u8; m.output_len()];
            m.finish(&a2, &mut out2).unwrap();
            assert_eq!(out, out2);
            assert_eq!(m.step(&mut a2, &mut c), Err(RunError::Finished));
        }
    }
}

#[test]
fn malformed_packages_are_refused_for_the_right_reason() {
    let good = s1_package();
    assert!(Model::admit(&good).is_ok());
    let alter = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut p = good.clone();
        f(&mut p);
        rehash(&mut p);
        Model::admit(&p).err()
    };
    // A flipped bit anywhere without re-hashing: integrity.
    for pos in [5usize, 40, 70, good.len() - 40] {
        let mut p = good.clone();
        p[pos] ^= 1;
        assert!(matches!(Model::admit(&p), Err(Refusal::Root) | Err(Refusal::Magic) | Err(Refusal::Version) | Err(Refusal::Length) | Err(Refusal::Counts) | Err(Refusal::Arch)), "pos {pos}");
    }
    assert_eq!(alter(&|p| p[0] = b'X'), Some(Refusal::Magic));
    assert_eq!(alter(&|p| p[4] = 9), Some(Refusal::Version));
    assert_eq!(alter(&|p| p[6] = 7), Some(Refusal::Arch));
    assert_eq!(alter(&|p| p[7] = 3), Some(Refusal::Target));
    assert_eq!(alter(&|p| p[24] = 1), Some(Refusal::Reserved));
    assert_eq!(alter(&|p| p[12..16].copy_from_slice(&20u32.to_le_bytes())), Some(Refusal::SlotOutOfArena)); // arena smaller than the plan
    assert_eq!(alter(&|p| p[12..16].copy_from_slice(&(1u32 << 20).to_le_bytes())), Some(Refusal::Counts));
    assert_eq!(alter(&|p| p[20] = 9), Some(Refusal::BadSlotIndex)); // input slot index
    let s0 = HEADER_LEN + 4 * SLOT_LEN; // first step
    assert_eq!(alter(&|p| p[s0] = 99), Some(Refusal::UnknownKernel));
    assert_eq!(alter(&|p| p[s0 + 8] = 27), Some(Refusal::Shape)); // cols 27 ≠ input length
    assert_eq!(alter(&|p| p[s0 + 12..s0 + 16].copy_from_slice(&50u32.to_le_bytes())), Some(Refusal::WeightsOutOfBounds));
    assert_eq!(alter(&|p| p[s0 + 4] = 3), Some(Refusal::Shape)); // output slot of the wrong length
    assert_eq!(alter(&|p| p.push(0)), Some(Refusal::Length)); // trailing byte
    assert_eq!(Model::admit(&good[..good.len() - 1]).err().is_some(), true);
    assert_eq!(Model::admit(&[]).err(), Some(Refusal::Length));
    // In-place use of a weighted kernel is refused.
    let w = vec![1u8; 4 + 8];
    let p = pack(&[(0, 2)], &[St { kernel: kernel::DENSE_I8, input: 0, output: 0, rows: 2, cols: 2, w_off: 0, b_off: 4, mult: 1, ..NONE }], &w, 2, 0, 0);
    assert_eq!(Model::admit(&p).err(), Some(Refusal::SlotsOverlap));
    // A model whose accumulator could overflow is refused, never wrapped.
    let mut w = Vec::new();
    for _ in 0..300 {
        w.extend_from_slice(&i16::MAX.to_le_bytes());
    }
    let b_off = w.len() as u32;
    w.extend_from_slice(&i32::MAX.to_le_bytes());
    let p = pack(&[(0, 300), (300, 4)], &[St { kernel: kernel::AFFINE_U8_I16, input: 0, output: 1, rows: 1, cols: 300, w_off: 0, b_off, ..NONE }], &w, 304, 0, 1);
    assert_eq!(Model::admit(&p).err(), Some(Refusal::AccumulatorBound));
    // Wrong buffer sizes at run time are errors, not panics.
    let m = Model::admit(&good).unwrap();
    let mut out = [0u8; 5];
    assert_eq!(m.run(&mut [0u8; 10], &[0; 28], &mut out), Err(RunError::ArenaTooSmall));
    assert_eq!(m.run(&mut [0u8; 33], &[0; 27], &mut out), Err(RunError::InputLength));
    assert_eq!(m.run(&mut [0u8; 33], &[0; 28], &mut [0u8; 4]), Err(RunError::OutputLength));
}

#[test]
fn fuzzed_packages_never_panic() {
    let mut rng = Rng(0xabad_1dea);
    let good = s1_package();
    let n: usize = std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(300_000);
    let (mut admitted, mut refused) = (0u32, 0u32);
    for i in 0..n {
        let mut p = good.clone();
        for _ in 0..=rng.below(4) {
            let pos = rng.below((p.len() - ROOT_LEN) as u64) as usize;
            p[pos] = if rng.below(2) == 0 { rng.next() as u8 } else { p[pos] ^ (1 << rng.below(8)) };
        }
        // Re-hash most of the time so mutations reach past the integrity check.
        if i % 8 != 0 {
            rehash(&mut p);
        }
        match Model::admit(&p) {
            Err(_) => refused += 1,
            Ok(m) => {
                admitted += 1;
                let mut arena = vec![0u8; m.arena_bytes()];
                let x: Vec<u8> = (0..m.input_len()).map(|_| rng.next() as u8).collect();
                let mut out = vec![0u8; m.output_len()];
                m.run(&mut arena, &x, &mut out).unwrap();
            }
        }
    }
    println!("fuzz: {admitted} admitted and run, {refused} refused");
    assert!(admitted > 100 && refused > 100);
}
