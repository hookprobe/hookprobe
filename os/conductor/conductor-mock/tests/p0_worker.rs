// SPDX-License-Identifier: AGPL-3.0-only
//! A worker whose compute is the native engine: the device's harness, the capability protocol, the worker
//! (`conductor-worker`), the engine session (`neuro_gguf::p0`) bound by `conductor-p0`, and back through the
//! verifier. No scripted answer anywhere: what comes back is what the integer engine decodes under Neuro's
//! contract from a signed bundle.
//!
//! The model is `tok_build::tiny_qwen3_gguf`: one block, every weight the same. Its answers mean nothing; they
//! are whatever the contract forces when every token scores the same (the lowest allowed token each time), which
//! makes the contract the only thing that shapes them. The last test uses seeded weights instead, so that the
//! answer depends on the arithmetic, and checks that nodes agree bit for bit.
use conductor_core::class::{DataClass, Tier};
use conductor_core::crypto::{public_key, sign, verify};
use conductor_core::harness::{Harness, Outcome as HOutcome};
use conductor_core::job::Verdict;
use conductor_core::verify::Status;
use conductor_mock::disk::{Disk, Platter};
use conductor_mock::*;
use conductor_p0::{code, shown_context, P0Executor};
use conductor_worker::{Executor, Layout, ResultKey, Run, Worker};
use neuro_gguf::hnx::{admit, manifest_for_bundle, Admitted};
use neuro_gguf::p0::{self, Mem, Session};
use neuro_hnx::{build_prefix, kind, scheme, target, Header, Loader, Platform, HEADER_LEN, LEAF_LEN, MAX_SIG};
use neuro_kernels::Simd;
use neuro_lm::qwen3::Layer;

const LAYOUT: Layout = Layout { high_water_lo: 64, epoch_lo: 66 };
const CTX: usize = 8192;
/// The tiny model's tokens are bytes, so its answers are several times longer in tokens than the explainer's.
const MAX_ANSWER: usize = 1600;
const SIGN_SEED: [u8; 32] = [0x77; 32];
const TAG: &[u8] = b"test/hnx";

struct SeedKey([u8; 32]);
impl ResultKey for SeedKey {
    fn public_key(&self) -> [u8; 32] {
        public_key(&self.0)
    }
    fn sign(&self, tag: &[u8], msg: &[u8]) -> Option<[u8; 64]> {
        sign(&self.0, tag, msg)
    }
}

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

/// Every byte is a token, plus the end-of-turn token the chat template uses.
fn tokens() -> Vec<Vec<u8>> {
    let mut t: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
    t.push(b"<|im_end|>".to_vec());
    t
}

/// The same vocabulary as a GGUF spells it: a token there is a UTF-8 string, so a byte above 127 is written as
/// the character with that number (as byte-level vocabularies do). The engine reads only how many there are;
/// the bytes of each token come from the tokenizer section.
fn gguf_tokens() -> Vec<Vec<u8>> {
    let mut t: Vec<Vec<u8>> = (0..=255u8).map(|b| char::from(b).to_string().into_bytes()).collect();
    t.push(b"<|im_end|>".to_vec());
    t
}

fn admitted(seed: Option<u64>) -> Admitted<'static> {
    admitted_bundle(bundle_bytes(seed))
}

/// The tiny model as a bundle payload: model file, tokenizer tables, RoPE pairs, no packed section.
fn bundle_bytes(seed: Option<u64>) -> &'static [u8] {
    let toks = tokens();
    let file = match seed {
        None => tok_build::tiny_qwen3_gguf(&gguf_tokens(), CTX as u32),
        Some(s) => tok_build::tiny_qwen3_gguf_seeded(&gguf_tokens(), CTX as u32, s),
    };
    let tok = tok_build::blob(&tok_build::Source { tokens: toks, merges: vec![], added: vec![256] }, &tok_build::unicode_ranges(), &tok_build::nfc_tables()).unwrap();
    let rope: Vec<u8> = (0..CTX * 16).flat_map(|i| if i % 3 == 0 { [0i32.to_le_bytes(), (1i32 << 30).to_le_bytes()].concat() } else { [(1i32 << 30).to_le_bytes(), 0i32.to_le_bytes()].concat() }).collect();
    tok_build::bundle([&file, &tok, &rope, &[]]).unwrap().leak()
}

/// Build, sign, load in place and admit the tiny model as a bundle: the node's start-up.
fn admitted_bundle(bundle: &'static [u8]) -> Admitted<'static> {
    let mut licence = [0u8; 32];
    licence[..13].copy_from_slice(b"AGPL-3.0-only");
    let mut h = Header {
        target: target::GENERIC_INT,
        scheme: scheme::ED25519,
        engine_abi: 1,
        segment_log2: 16,
        n_segments: 0,
        model_id: [9; 16],
        model_svn: 1,
        manifest: manifest_for_bundle(bundle, CTX).unwrap(),
        licence,
        source_sha256: [1; 32],
        eval_sha256: [2; 32],
        merkle_root: [0; 32],
        payload_kind: kind::LM_BUNDLE,
    };
    let mut prefix = vec![0u8; HEADER_LEN + bundle.len().div_ceil(1 << 16) * LEAF_LEN + 2 + 64];
    let n = build_prefix(&mut h, bundle, &mut prefix, |d| {
        let mut out = [0u8; MAX_SIG];
        out[..64].copy_from_slice(&sign(&SIGN_SEED, TAG, d)?);
        Some((out, 64))
    })
    .unwrap();
    prefix.truncate(n);
    let prefix: &'static [u8] = prefix.leak();
    let mut l = Loader::open(prefix, &Node).unwrap();
    let region: &'static mut [u8] = vec![0u8; bundle.len()].leak();
    for i in 0..l.header().n_segments {
        let (s, e) = (i as usize * 65536, ((i as usize + 1) * 65536).min(bundle.len()));
        region[s..e].copy_from_slice(&bundle[s..e]);
        l.accept_in_place(i, region).unwrap();
    }
    admit(&l, region).unwrap()
}

type Exec = P0Executor<'static, Box<dyn FnMut() -> u64>>;

/// The node's compute: one session on the admitted model, serving `model`.
fn executor(model: [u8; 32]) -> Exec {
    executor_on(model, Simd::SCALAR, None)
}

/// The fastest kernels this host has (NEON with dot product on an Apple or A76-class core).
fn fastest() -> Simd {
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("dotprod") {
        // SAFETY: the feature was detected on this CPU just above.
        return unsafe { Simd::neon_dot() };
    }
    Simd::SCALAR
}

fn executor_on(model: [u8; 32], simd: Simd, seed: Option<u64>) -> Exec {
    let ad: &'static Admitted<'static> = Box::leak(Box::new(admitted(seed)));
    let z = p0::sizes(&ad.hparams, 16);
    let mem = Mem {
        layers: vec![Layer::EMPTY; z.layers].leak(),
        rope: vec![(0, 0); z.rope].leak(),
        kv_vals: vec![0; z.kv_vals].leak(),
        kv_shifts: vec![0; z.kv_shifts].leak(),
        work_i64: vec![0; z.work_i64].leak(),
        work_i8: vec![0; z.work_i8].leak(),
        work_pairs: vec![(0, 0); z.work_pairs].leak(),
        work_i32: vec![0; z.work_i32].leak(),
        ids: vec![0; z.ids].leak(),
        prev: vec![0; z.prev].leak(),
        list: vec![0; 512].leak(),
        out: vec![0; MAX_ANSWER].leak(),
    };
    let session = Session::open(ad, simd, 16, mem).unwrap();
    let mut t = 0u64;
    let clock: Box<dyn FnMut() -> u64> = Box::new(move || {
        t += 3;
        t
    });
    P0Executor::new(session, model, vec![0u32; 1 << 15].leak(), vec![0u8; 1 << 15].leak(), clock).with_max_answer(MAX_ANSWER)
}

struct Real(Worker<Disk, SeedKey, Exec>);
impl Remote for Real {
    fn tier(&self) -> Tier {
        Tier::P1
    }
    fn receive(&mut self, tx: &[u8], session: &[u8; 32], now_ms: u64) -> Vec<Vec<u8>> {
        let mut v = vec![];
        self.0.handle(tx, session, now_ms, &mut |f| v.push(f.to_vec()));
        v
    }
}

fn node(model: [u8; 32]) -> Real {
    Real(Worker::boot(Disk::new(&Platter::default()), LAYOUT, SeedKey(WORKER_SEED), executor(model), public_key(&DEVICE_SEED), Tier::P1).expect("store readable"))
}

/// One device (its capability counter goes on from job to job) and one node.
fn device() -> Kernel {
    Kernel::new(policy_p1(), Tier::P1)
}

fn run(k: &mut Kernel, w: &mut Real, job: &JobBuilder) -> (Report, String) {
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &job.encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), w);
    let summary = String::from_utf8_lossy(h.summary()).into_owned();
    (r, summary)
}

#[test]
fn a_job_runs_on_the_native_engine_through_the_whole_protocol() {
    let (mut k, mut w) = (device(), node(MODEL));
    // With every token scoring the same, the contract alone shapes the answer: "benign", nothing cited. So the
    // job here requires no citation; the next test shows the verifier holding back the same answer when it does.
    let evidence = vec![Ev { id: 1, class: DataClass::Public, required: false, text: "42 connections to 203.0.113.9:443 in 10 min".into() }];
    let job = JobBuilder { tools: 0, l0: Verdict::Benign as u8, out_total: 4096, compute_total: 600_000, per_call: 120_000, evidence, ..Default::default() };
    let (r, summary) = run(&mut k, &mut w, &job);
    let Some(HOutcome::Verified(v)) = r.outcome else { panic!("expected a verified answer, got {:?}", r.outcome) };
    assert_eq!((v.status, v.model_verdict, v.l0_decided), (Status::Valid, Some(Verdict::Benign), true));
    assert!(!summary.is_empty());
    assert_eq!(r.leases_started, r.leases_ended);
    // The engine really ran: prompt passes, answer passes, an answer that ended by itself within its bound.
    let st = w.0.executor().last_stats();
    assert!(st.prefill_passes > 50 && st.passes > 100, "{st:?}");
    assert!((st.tokens as usize) < MAX_ANSWER, "the answer closed under the contract before the bound: {st:?}");

    // A second job on the same node: a new capability, a new counter, and the prompt's identical start is not
    // fed again.
    let (r2, _) = run(&mut k, &mut w, &JobBuilder { job_id: [8; 16], ..job.clone() });
    assert!(matches!(r2.outcome, Some(HOutcome::Verified(v)) if v.status == Status::Valid), "{:?}", r2.outcome);
    assert!(w.0.executor().last_reused() > 100, "reused {}", w.0.executor().last_reused());
    assert!(w.0.executor().last_stats().prefill_passes < st.prefill_passes);
    assert_eq!(w.0.high_water(), 2);
}

#[test]
fn the_verifier_holds_back_an_engine_answer_that_cites_nothing_required() {
    // The default job marks a fact as required. The tiny model cites nothing, and no engine output is trusted for
    // being well formed: the device's verifier reports the answer incomplete.
    let (mut k, mut w) = (device(), node(MODEL));
    let job = JobBuilder { tools: 0, l0: Verdict::Benign as u8, out_total: 4096, compute_total: 600_000, per_call: 120_000, ..Default::default() };
    let (r, _) = run(&mut k, &mut w, &job);
    assert!(matches!(r.outcome, Some(HOutcome::Verified(v)) if v.status == Status::Incomplete), "{:?}", r.outcome);
}

#[test]
fn the_node_refuses_what_it_does_not_serve() {
    // Another model digest than the one this node admitted: an ERROR frame, and the device aborts the job.
    let (mut k, mut w) = (device(), node([0x99; 32]));
    let job = JobBuilder { tools: 0, out_total: 4096, compute_total: 600_000, per_call: 120_000, ..Default::default() };
    let (r, _) = run(&mut k, &mut w, &job);
    assert!(matches!(r.outcome, Some(HOutcome::Aborted(_))), "{:?}", r.outcome);
    assert_eq!(w.0.executor().last_stats().tokens, 0, "nothing was decoded");

    // The executor alone: not `infer`; a prompt with no context block; a context with no fact.
    let mut e = executor(MODEL);
    let mut out = [0u8; 256];
    assert_eq!(e.run(conductor_core::cap::op::EMBED, &MODEL, b"x", &mut out).err(), Some(code::UNSUPPORTED));
    assert_eq!(e.run(conductor_core::cap::op::INFER, &MODEL, b"tell me a story", &mut out).err(), Some(code::PROMPT));
    let no_fact = format!("{}REST 0 more cards omitted{}Assess this window.", neuro_contract::USER_HEAD, neuro_contract::USER_MID);
    assert_eq!(e.run(conductor_core::cap::op::INFER, &MODEL, no_fact.as_bytes(), &mut out).err(), Some(code::PROMPT));
    // An answer that does not fit the output the capability allows.
    let ok = format!("{}F1 H1->R1:443 n=3{}Assess this window.", neuro_contract::USER_HEAD, neuro_contract::USER_MID);
    assert_eq!(shown_context(ok.as_bytes()), Some(&b"F1 H1->R1:443 n=3"[..]));
    assert_eq!(e.run(conductor_core::cap::op::INFER, &MODEL, ok.as_bytes(), &mut [0u8; 8]).err(), Some(code::OUTPUT));
    let mut big = vec![0u8; 8192];
    let run = e.run(conductor_core::cap::op::INFER, &MODEL, ok.as_bytes(), &mut big).unwrap();
    let text = std::str::from_utf8(&big[..run.len]).unwrap();
    // Tabs wherever the grammar allows white space (the lowest allowed token), and still one whole answer.
    let dense: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(dense.starts_with("{\"verdict\":\"benign\"") && dense.ends_with('}'), "{text}");
    assert!(run.compute_ms > 0 && run.ttft_ms > 0 && run.ttft_ms <= run.compute_ms);
}

/// What the fleet's verified redundancy stands on (ADR 0071 amendment A3, `conductor_core::quorum`): honest
/// nodes give the same bytes. Three nodes run the same request on the same model with different kernels and
/// different histories; their signed results agree exactly. A node with other weights is a conflict with
/// evidence. The model's weights are drawn from a seed, so tokens score differently and the answer depends on
/// the arithmetic of every pass.
#[test]
fn engine_nodes_agree_bit_for_bit_and_a_wrong_one_is_caught() {
    use conductor_core::crypto::{sha256, TAG_RESULT};
    use conductor_core::frame::{result_message, Usage};
    use conductor_core::quorum::{Outcome, Quorum, Vote};
    let ask = |ctx: &str| format!("{}{ctx}{}Assess this window.", neuro_contract::USER_HEAD, neuro_contract::USER_MID);
    let request = ask("F1 H1->R1:443 n=3 bytes=1200\nF2 H1->R2:53 n=40 bytes=5200\nF3 H2->R1:22 n=1 bytes=90");
    let other = ask("F1 H3->R4:8443 n=7 bytes=300");
    let request_hash = sha256(&[request.as_bytes()]);
    let answer = |e: &mut Exec, prompt: &str| -> (Vec<u8>, Run) {
        let mut out = vec![0u8; 8192];
        let run = e.run(conductor_core::cap::op::INFER, &MODEL, prompt.as_bytes(), &mut out).unwrap();
        out.truncate(run.len);
        (out, run)
    };
    let vote = |i: u8, out: &[u8], run: &Run| -> Vote {
        let seed = sha256(&[b"p0-exact-node", &[i]]);
        let cap_id = [i; 16];
        let (output_hash, usage) = (sha256(&[out]), Usage { in_units: 0, out_units: out.len() as u32, compute_ms: run.compute_ms + u32::from(i), ttft_ms: run.ttft_ms });
        let sig = sign(&seed, TAG_RESULT, &result_message(&cap_id, &request_hash, &output_hash, 1, &usage)).unwrap();
        Vote { worker_pk: public_key(&seed), cap_id, output_hash, seq: 1, usage, sig }
    };

    // Node 1: scalar kernels, first job. Node 2: this host's fastest kernels. Node 3: scalar, after another job,
    // so its cache holds a prompt start it reuses.
    let mut n1 = executor_on(MODEL, Simd::SCALAR, Some(7));
    let (a1, r1) = answer(&mut n1, &request);
    let mut n2 = executor_on(MODEL, fastest(), Some(7));
    let (a2, r2) = answer(&mut n2, &request);
    let mut n3 = executor_on(MODEL, Simd::SCALAR, Some(7));
    let (b3, _) = answer(&mut n3, &other);
    let (a3, r3) = answer(&mut n3, &request);
    assert!(n3.last_reused() > 20 && n1.last_reused() == 0, "{} {}", n3.last_reused(), n1.last_reused());
    assert_ne!(a1, b3, "another context gives another answer: the model is not constant");
    assert_eq!(a1, a2, "scalar and SIMD kernels");
    assert_eq!(a1, a3, "fresh and reused cache");
    let mut q = Quorum::new(request_hash, 3).unwrap();
    q.offer(vote(1, &a1, &r1)).unwrap();
    q.offer(vote(2, &a2, &r2)).unwrap();
    assert_eq!(q.offer(vote(3, &a3, &r3)), Ok(Outcome::Agreed { output_hash: sha256(&[&a1]) }));

    // A node whose weights differ (a corrupted or substituted model that still claims the digest).
    let mut bad = executor_on(MODEL, Simd::SCALAR, Some(8));
    let (w, rw) = answer(&mut bad, &request);
    assert_ne!(w, a1);
    let mut q = Quorum::new(request_hash, 3).unwrap();
    q.offer(vote(1, &a1, &r1)).unwrap();
    let Ok(Outcome::Conflict(c)) = q.offer(vote(4, &w, &rw)) else { panic!("expected a conflict") };
    assert!(c.is_valid_evidence());
    assert_eq!(q.disagrees_with(&sha256(&[&a1])).map(|v| v.cap_id).collect::<Vec<_>>(), vec![[4u8; 16]]);
    println!("exact agreement: {} answer bytes, {} tokens, scalar = SIMD = reused cache; other weights caught", a1.len(), n1.last_stats().tokens);
}

/// The engine as a worker-core job (`conductor_p0::core_job`, ADR 0060 S2): the prompt lies in the window core 0
/// granted, the answer goes to the result window behind a header of counters, and core 0 follows and stops the
/// job through two shared words. The answer is the one the capability path gives for the same prompt.
#[test]
fn the_engine_op_for_a_worker_core() {
    use conductor_p0::core_job::{self, op, refused_with, status, Link, CANCELLED, HEADER};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    let prompt = format!("{}F1 H1->R1:443 n=3 bytes=1200\nF2 H2->R1:22 n=1 bytes=90{}Assess this window.", neuro_contract::USER_HEAD, neuro_contract::USER_MID);
    // The granted window: other bytes around the prompt.
    let mut window = vec![0xA5u8; 64];
    let at = window.len() as u64;
    window.extend_from_slice(prompt.as_bytes());
    window.extend_from_slice(&[0x5A; 32]);
    let len = prompt.len() as u64;
    let (progress, cancel) = (AtomicU32::new(7), AtomicBool::new(false));
    let mut core = executor_on(MODEL, fastest(), Some(7));
    let mut result = vec![0u8; 8192];

    let link = Link { window: &window, progress: &progress, cancel: &cancel };
    let (st, value) = core_job::run(&mut core, op::ENGINE_INFER, at, len, link, &mut result);
    assert_eq!(st, status::OK);
    let answer = &result[HEADER..HEADER + value as usize];
    let word = |i: usize| u32::from_le_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
    let stats = core.last_stats();
    assert_eq!((word(0), word(1), word(2), word(3)), (stats.tokens, stats.prefill_passes, stats.passes, 0));
    assert_eq!(progress.load(Ordering::Acquire), stats.tokens, "core 0 saw the last pass");
    // The same bytes as a node answering the same prompt through the capability path, on other kernels.
    let mut node = executor_on(MODEL, Simd::SCALAR, Some(7));
    let mut out = vec![0u8; 8192];
    let run = node.run(conductor_core::cap::op::INFER, &MODEL, prompt.as_bytes(), &mut out).unwrap();
    assert_eq!(answer, &out[..run.len]);

    // What core 0 may get wrong, and what the engine refuses.
    let mut call = |op: u32, a: u64, b: u64, result: &mut [u8], _: &AtomicBool| core_job::run(&mut core, op, a, b, link, result);
    assert_eq!(call(0x7777, at, len, &mut result, &cancel), (status::UNKNOWN_OP, 0));
    assert_eq!(call(op::ENGINE_INFER, at, window.len() as u64, &mut result, &cancel), (status::OUT_OF_WINDOW, 0), "runs past the window");
    assert_eq!(call(op::ENGINE_INFER, u64::MAX, 2, &mut result, &cancel), (status::OUT_OF_WINDOW, 0), "overflows");
    assert_eq!(call(op::ENGINE_INFER, at, len, &mut [0u8; HEADER - 1], &cancel), (status::OUT_OF_WINDOW, 0), "no room for the header");
    let (st, value) = call(op::ENGINE_INFER, 0, 64, &mut result, &cancel);
    assert!(refused_with(st, code::PROMPT) && value == 0, "bytes that are not a prompt: {st:#x}");
    let (st, value) = call(op::ENGINE_INFER, at, len, &mut [0u8; HEADER + 8], &cancel);
    assert!(refused_with(st, code::OUTPUT) && value == 0, "an answer that does not fit is not cut: {st:#x}");

    // Core 0 stops the job: it ends after the pass in flight and returns nothing of an answer.
    cancel.store(true, Ordering::Release);
    result.fill(0);
    let (st, value) = call(op::ENGINE_INFER, at, len, &mut result, &cancel);
    assert_eq!((st, value), (CANCELLED, 0));
    assert!(result[HEADER..].iter().all(|b| *b == 0), "no partial answer in the result window");
    // And the core serves the next job as if nothing had happened: the same bytes again.
    cancel.store(false, Ordering::Release);
    let (st, value) = call(op::ENGINE_INFER, at, len, &mut result, &cancel);
    assert_eq!(st, status::OK);
    assert_eq!(&result[HEADER..HEADER + value as usize], &out[..run.len]);
}

/// Moves a value that is used by one thread at a time into another thread.
struct Handed<T>(T);
// SAFETY: the value is built on the test thread and then used only by the one thread it is moved into.
unsafe impl<T> Send for Handed<T> {}
impl<T> Handed<T> {
    fn take(self) -> T {
        self.0
    }
}

const PAINT: u64 = 0x5AA5_C33C_0FF0_9669;
/// Stack below the caller that is left alone, so the painting and scanning code cannot overwrite itself.
const PAINT_GAP: usize = 2048;

/// Runs `f` and returns how many bytes of stack below this frame it touched (its high-water mark), by painting
/// `span` bytes of unused stack first. A depth under `PAINT_GAP` is reported as `PAINT_GAP`.
#[inline(never)]
fn stack_used<R>(span: usize, f: impl FnOnce() -> R) -> (R, usize) {
    let here = 0u8;
    let top = (std::hint::black_box(&here) as *const u8 as usize) & !7;
    let (lo, hi) = (top - span, top - PAINT_GAP);
    let mut a = lo;
    while a < hi {
        // SAFETY: [lo, hi) lies inside this thread's own stack (the caller made it larger than `span`), below
        // every live frame: nothing reads these words before the callee writes them.
        unsafe { (a as *mut u64).write_volatile(PAINT) };
        a += 8;
    }
    let r = f();
    let mut a = lo;
    // SAFETY: the same range, read back.
    while a < hi && unsafe { (a as *const u64).read_volatile() } == PAINT {
        a += 8;
    }
    assert!(a > lo, "the callee went deeper than the painted span");
    (r, top - a)
}

#[inline(never)]
fn burn(depth: usize) -> usize {
    let a = std::hint::black_box([depth as u8; 1024]);
    if depth == 0 {
        a[0] as usize
    } else {
        burn(depth - 1) + std::hint::black_box(a[depth % 1024] as usize)
    }
}

/// The engine job on a thread of its own. Returns the status, the answer and the stack the job used.
fn job_with_stack_measured(simd: Simd) -> (u32, Vec<u8>, usize) {
    use conductor_p0::core_job::{self, op, Link, HEADER};
    use std::sync::atomic::{AtomicBool, AtomicU32};
    let prompt = format!("{}F1 H1->R1:443 n=3 bytes=1200\nF2 H2->R1:22 n=1 bytes=90{}Assess this window.", neuro_contract::USER_HEAD, neuro_contract::USER_MID);
    let handed = Handed((executor_on(MODEL, simd, Some(7)), vec![0u8; 8192], prompt.into_bytes()));
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let (mut core, mut result, window) = handed.take();
            let (progress, cancel) = (AtomicU32::new(0), AtomicBool::new(false));
            let link = Link { window: &window, progress: &progress, cancel: &cancel };
            let ((st, value), used) = stack_used(256 * 1024, || core_job::run(&mut core, op::ENGINE_INFER, 0, window.len() as u64, link, &mut result));
            (st, result[HEADER..HEADER + value as usize].to_vec(), used)
        })
        .unwrap()
        .join()
        .unwrap()
}

/// The stack a worker core gets (`os/kernel/arch-aarch64/src/smp.rs`, `STACK_SIZE`), and what of it the engine
/// job may use: the rest is for the worker executive's own frames and an exception entry.
const WORKER_STACK: usize = 16 * 1024;
const ENGINE_STACK_BUDGET: usize = 12 * 1024;

#[test]
fn the_engine_job_fits_a_worker_core_stack() {
    // The measurement measures: nine frames of a little over 1 KiB each.
    let (_, cal) = std::thread::Builder::new().stack_size(1 << 20).spawn(|| stack_used(256 * 1024, || burn(8))).unwrap().join().unwrap();
    assert!(cal >= 9 * 1024, "the stack measurement saw only {cal} bytes of a 9 KiB recursion");
    let (st, fast, used_fast) = job_with_stack_measured(fastest());
    let (st2, scalar, used_scalar) = job_with_stack_measured(Simd::SCALAR);
    assert_eq!((st, st2), (0, 0));
    assert_eq!(fast, scalar, "the same answer on both kernel sets");
    println!("engine job stack: {used_fast} bytes (fastest kernels), {used_scalar} bytes (scalar); worker stack {WORKER_STACK}");
    // The bound is checked where it means something: an optimised build for the device's architecture. An
    // unoptimised build uses several times more and is not what a device runs.
    if cfg!(all(target_arch = "aarch64", not(debug_assertions))) {
        assert!(used_fast.max(used_scalar) <= ENGINE_STACK_BUDGET, "the engine job used {used_fast}/{used_scalar} bytes of stack; budget {ENGINE_STACK_BUDGET} of {WORKER_STACK}");
    }
}

// ---------------------------------------------------------------- the entry over raw regions (ADR 0060 S2b)

mod entry {
    use super::*;
    use conductor_engine_entry::{self as ee, arena_need, engine_infer, InferArgs, Limits};
    use conductor_p0::core_job::{op, refused_with, status, Link, CANCELLED, HEADER};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    const LIMITS: Limits = Limits { max_ctx: CTX as u32, max_answer: MAX_ANSWER as u32 };

    fn prompt() -> Vec<u8> {
        format!("{}F1 H1->R1:443 n=3 bytes=1200\nF2 H2->R1:22 n=1 bytes=90{}Assess this window.", neuro_contract::USER_HEAD, neuro_contract::USER_MID).into_bytes()
    }

    /// The answer the capability path gives for the same model and prompt.
    fn reference() -> Vec<u8> {
        let mut node = executor_on(MODEL, Simd::SCALAR, Some(7));
        let mut out = vec![0u8; 8192];
        let run = node.run(conductor_core::cap::op::INFER, &MODEL, &prompt(), &mut out).unwrap();
        out[..run.len].to_vec()
    }

    struct Call<'a> {
        model: &'a [u8],
        arena: &'a mut [u8],
        window: &'a [u8],
        result: &'a mut [u8],
        cancel: bool,
        limits: Limits,
        op: u32,
        path: u32,
    }

    /// Through the C entry, as an engine image's stub would call it. Returns status, value, progress word.
    fn call(c: Call) -> (u32, u64, u32) {
        let (progress, cancel) = (AtomicU32::new(9), AtomicBool::new(c.cancel));
        let mut value = u64::MAX;
        let args = InferArgs {
            model: c.model.as_ptr(),
            model_len: c.model.len() as u64,
            arena: c.arena.as_mut_ptr(),
            arena_len: c.arena.len() as u64,
            window: c.window.as_ptr(),
            window_len: c.window.len() as u64,
            result: c.result.as_mut_ptr(),
            result_len: c.result.len() as u64,
            progress: &progress,
            cancel: &cancel,
            value: &mut value,
            a: 0,
            b: c.window.len() as u64,
            limits: c.limits,
            op: c.op,
            path: c.path,
        };
        // SAFETY: the regions are live, distinct slices of the stated lengths; the words are live; SDOT is
        // passed only when the host has it (`sdot()`).
        let st = unsafe { engine_infer(&args) };
        (st, value, progress.load(Ordering::Acquire))
    }

    fn sdot() -> bool {
        fastest().is_neon()
    }

    #[test]
    fn raw_regions_in_the_same_bytes_out() {
        let model = bundle_bytes(Some(7));
        let need = arena_need(model, LIMITS).unwrap() as usize;
        let want = reference();
        let window = prompt();
        // What is in the arena before a call does not matter, and neither does where it starts.
        let mut arena = vec![0xEEu8; need + 1];
        let mut result = vec![0u8; 8192];
        let mut paths = vec![ee::path::SCALAR];
        if sdot() {
            paths.push(ee::path::SDOT);
        }
        for path in paths {
            for skew in [0usize, 1] {
                result.fill(0);
                let (st, value, progress) = call(Call { model, arena: &mut arena[skew..], window: &window, result: &mut result, cancel: false, limits: LIMITS, op: op::ENGINE_INFER, path });
                assert_eq!(st, status::OK, "path {path} skew {skew}");
                assert_eq!(&result[HEADER..HEADER + value as usize], &want[..], "path {path} skew {skew}: the capability path's bytes");
                let word = |i: usize| u32::from_le_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                assert_eq!(progress, word(0), "core 0 saw the last pass");
                assert_eq!(word(3), 0, "a call starts from an empty cache");
            }
        }
        // The safe form, on the same arena as the calls above left it.
        let (progress, cancel) = (AtomicU32::new(0), AtomicBool::new(false));
        result.fill(0);
        let (st, value) = ee::run(ee::Job { model, arena: &mut arena, limits: LIMITS, simd: fastest(), op: op::ENGINE_INFER, a: 0, b: window.len() as u64, link: Link { window: &window, progress: &progress, cancel: &cancel }, result: &mut result });
        assert_eq!((st, &result[HEADER..HEADER + value as usize]), (status::OK, &want[..]));
    }

    #[test]
    fn what_the_entry_refuses() {
        let model = bundle_bytes(Some(7));
        let need = arena_need(model, LIMITS).unwrap() as usize;
        let window = prompt();
        let mut arena = vec![0u8; need];
        let mut result = vec![0u8; 8192];
        macro_rules! refuse {
            ($what:literal, $code:expr, $($field:ident: $v:expr),*) => {{
                result.fill(0);
                let (st, value, _) = call(Call { $($field: $v,)* ..Call { model, arena: &mut arena, window: &window, result: &mut result, cancel: false, limits: LIMITS, op: op::ENGINE_INFER, path: ee::path::SCALAR } });
                assert!(refused_with(st, $code), "{}: {st:#x}", $what);
                assert_eq!(value, 0, "{}", $what);
            }};
        }
        let mut small = vec![0u8; need / 2];
        refuse!("an arena that is too small", ee::code::ARENA, arena: &mut small);
        refuse!("no arena", ee::code::ARENA, arena: &mut []);
        refuse!("a cut model region", ee::code::MODEL, model: &model[..model.len() - 1]);
        let mut bent = model.to_vec();
        bent[..8].fill(0xFF);
        refuse!("a region that is not a bundle", ee::code::MODEL, model: &bent);
        refuse!("another context than the tables were made for", ee::code::MODEL, limits: Limits { max_ctx: CTX as u32 * 2, ..LIMITS });
        refuse!("an answer bound out of range", ee::code::LIMITS, limits: Limits { max_answer: ee::MAX_ANSWER_LIMIT + 1, ..LIMITS });
        refuse!("a kernel set this build does not have", ee::code::KERNELS, path: 1);
        refuse!("bytes that are not a prompt", conductor_p0::code::PROMPT, window: &[0xA5; 64]);
        assert!(result[HEADER..].iter().all(|b| *b == 0), "a refusal writes no answer");

        let (st, value, _) = call(Call { model, arena: &mut arena, window: &window, result: &mut result, cancel: false, limits: LIMITS, op: 0x7777, path: ee::path::SCALAR });
        assert_eq!((st, value), (status::UNKNOWN_OP, 0));
        let (st, value, _) = call(Call { model, arena: &mut arena, window: &window, result: &mut result, cancel: true, limits: LIMITS, op: op::ENGINE_INFER, path: ee::path::SCALAR });
        assert_eq!((st, value), (CANCELLED, 0), "core 0 had already stopped it");
        // SAFETY: a null argument block is refused before anything is read.
        assert!(refused_with(unsafe { engine_infer(std::ptr::null()) }, ee::code::NULL));
        assert!(refused_with(arena_need(&bent, LIMITS).unwrap_err(), ee::code::MODEL));
    }

    #[test]
    fn the_whole_entry_fits_a_worker_core_stack() {
        // Unlike `the_engine_job_fits_a_worker_core_stack`, this includes opening the model and the session.
        let model = bundle_bytes(Some(7));
        let need = arena_need(model, LIMITS).unwrap() as usize;
        let handed = Handed((vec![0u8; need], vec![0u8; 8192], prompt(), fastest()));
        let (st, used) = std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || {
                let (mut arena, mut result, window, simd) = handed.take();
                let (progress, cancel) = (AtomicU32::new(0), AtomicBool::new(false));
                let job = ee::Job { model, arena: &mut arena, limits: LIMITS, simd, op: op::ENGINE_INFER, a: 0, b: window.len() as u64, link: Link { window: &window, progress: &progress, cancel: &cancel }, result: &mut result };
                let ((st, _), used) = stack_used(256 * 1024, || ee::run(job));
                (st, used)
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(st, status::OK);
        println!("engine entry stack: {used} bytes; arena {need} bytes for the test model; worker stack {WORKER_STACK}");
        if cfg!(all(target_arch = "aarch64", not(debug_assertions))) {
            assert!(used <= ENGINE_STACK_BUDGET, "the entry used {used} bytes of stack; budget {ENGINE_STACK_BUDGET} of {WORKER_STACK}");
        }
    }
}
