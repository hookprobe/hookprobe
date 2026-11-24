// SPDX-License-Identifier: AGPL-3.0-only
//! C2 reference worker, end to end over real loopback TCP and heqk's real PQ-hybrid Noise handshake:
//! pairing, quotes, capability-gated execution, signed results, replay across restart, kill switch.

use conductor_core::cap::{self, SignRequest};
use conductor_core::class::Tier;
use conductor_core::crypto::{public_key, sha256, verify, TAG_RESULT};
use conductor_core::frame::{result_message, Body, Quote, QuoteRequest, Request, Response};
use conductor_core::signer::Signer;
use conductor_mock::{owner_pairing, policy_p1, MemCounter, DEVICE_SEED, EGRESS, MODEL, OWNER_SEED, SALT_KEY};
use conductor_worker::chan::{kind, Chan};
use conductor_worker::engine::{Engine, GenRequest, OpenAiCompat, Scripted};
use conductor_worker::entropy::OsEntropy;
use conductor_worker::files::{Keys, Paired, State};
use conductor_worker::pairio;
use conductor_worker::quote::{IdleProbe, Profile};
use conductor_worker::securechannel::ResponderPub;
use conductor_worker::serve::Worker;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const ANSWER: &str = r#"{"answer":{"cites":["ev:1"],"summary":"Exploit attempt matching the CVE."}}"#;
const IDENTITY_SEED: [u8; 32] = [0x99; 32];

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cw-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn identity() -> ed25519_compact::KeyPair {
    ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(IDENTITY_SEED))
}
fn worker_pub(keys: &Keys) -> ResponderPub {
    let b = keys.channel_blob();
    let mut x = [0u8; 32];
    x.copy_from_slice(&b[..32]);
    ResponderPub::from_provisioned(x, &b[32..]).unwrap()
}

/// Pair over real TCP; returns the worker dir (keys + paired saved) and the device's signer.
fn paired(name: &str) -> (PathBuf, Signer<MemCounter>) {
    let dir = tmp(name);
    Keys::generate(&dir).unwrap();
    let keys = Keys::load(&dir).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let dpk = public_key(&DEVICE_SEED);
    let ipk = *identity().pk;
    let dev = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        pairio::device_pair(&mut s, &dpk, &ipk, 1, [7; 16]).unwrap()
    });
    let (mut s, _) = l.accept().unwrap();
    let mut shown = 0;
    let w = pairio::worker_pair(&mut s, &keys, [8; 16], &mut |c| {
        shown = c;
        true
    })
    .unwrap();
    let d = dev.join().unwrap();
    assert_eq!(d.code, shown, "both screens show the same six digits");
    assert_eq!(d.worker_result_pk, keys.result_pk());
    w.paired.save(&dir).unwrap();
    let mut signer = Signer::new(DEVICE_SEED, SALT_KEY, public_key(&OWNER_SEED), policy_p1(), MemCounter(0));
    let (rec, sig) = owner_pairing(Tier::P1, keys.result_pk(), u64::MAX, 1);
    signer.install_pairing(&rec, &sig).unwrap();
    (dir, signer)
}

/// Start a worker serving `conns` connections with a scripted engine; returns its address and the seen log.
fn spawn_worker(dir: PathBuf, outputs: Vec<&str>, conns: usize, delay_ms: u64) -> (std::net::SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<(String, u8, [u8; 32])>>>, std::thread::JoinHandle<conductor_worker::serve::Stats>) {
    let mut eng = Scripted::new(outputs.into_iter().map(String::from).collect());
    eng.delay = Duration::from_millis(delay_ms);
    let seen = eng.seen.clone();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let mut w = Worker::open(dir.clone(), eng, IdleProbe { cmd: None, timeout: Duration::from_secs(1) }).unwrap();
        w.log = |_| {};
        w.profile = Profile { offload: 1, ttft_base_ms: 100, ttft_per_kunit_ms: 200, tpot_ms: 30 };
        let resp = Keys::load(&dir).unwrap().noise;
        let id = w.paired.channel_identity_pk;
        for _ in 0..conns {
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            if let Ok(mut c) = Chan::accept(s, &resp, &id, &mut OsEntropy) {
                w.serve(&mut c);
            }
        }
        w.stats
    });
    (addr, seen, h)
}

fn connect(addr: std::net::SocketAddr, dir: &PathBuf) -> Chan {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    Chan::connect(s, &identity(), &worker_pub(&Keys::load(dir).unwrap()), &mut OsEntropy).unwrap()
}

fn request(prompt: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; prompt.len() + 64];
    let n = Request { op: cap::op::INFER, model_digest: MODEL, prompt }.encode(&mut b).unwrap();
    b.truncate(n);
    b
}

fn sign_req(dir: &PathBuf, binding: [u8; 32], req: &[u8]) -> SignRequest {
    SignRequest {
        tier: 1,
        worker_public_key: Keys::load(dir).unwrap().result_pk(),
        session_binding: binding,
        job_id: [1; 16],
        request_hash: sha256(&[req]),
        model_digest: MODEL,
        operations: cap::op::INFER,
        data_classes: 1,
        egress_policy_id: EGRESS,
        max_input_units: 2048,
        max_output_units: 512,
        max_compute_ms: 5_000,
        max_response_bytes: 2048,
        ttl_ms: 60_000,
        slo_ttft_ms: 0,
        slo_tpot_ms: 0,
        affinity_id: [0; 16],
        cache_scope: 0,
        kv_persist: 0,
        offload_hints: 0,
        energy_policy: 0,
    }
}

fn exec(c: &mut Chan, signed: &[u8], req: &[u8]) {
    let mut m = signed.to_vec();
    m.extend_from_slice(req);
    c.send(kind::EXEC, &m).unwrap();
}

/// Read RESPONSE frames to the end; returns (output, final frame fields) or the refusal/err.
fn collect(c: &mut Chan) -> Result<(Vec<u8>, [u8; 16], u32, conductor_core::frame::Usage, [u8; 32], [u8; 64]), String> {
    let mut out = vec![];
    loop {
        let (k, m) = c.recv().map_err(|e| e.to_string())?;
        if k == kind::REFUSE {
            return Err(format!("REFUSE {:?}", m));
        }
        assert_eq!(k, kind::RESPONSE);
        let r = Response::decode(&m).ok_or("bad frame")?;
        match r.body {
            Body::Chunk(d) => out.extend_from_slice(d),
            Body::Error(e) => return Err(format!("ERROR {e}")),
            Body::Final { usage, output_hash, sig } => return Ok((out, r.capability_id, r.seq, usage, output_hash, sig)),
        }
    }
}

#[test]
fn pair_quote_execute_and_verify() {
    let (dir, mut signer) = paired("happy");
    let (addr, seen, h) = spawn_worker(dir.clone(), vec![ANSWER], 1, 0);
    let mut c = connect(addr, &dir);
    // Data-free quote, signed and nonce-bound.
    let q = QuoteRequest { job_id: [1; 16], model_digest: MODEL, in_units: 500, max_out_units: 256, slo_ttft_ms: 1_000, slo_tpot_ms: 50, offload_hints: 0, energy_policy: 0, nonce: [5; 16] };
    let mut qb = [0u8; 128];
    let n = q.encode(&mut qb).unwrap();
    c.send(kind::QUOTE_REQ, &qb[..n]).unwrap();
    let (k, m) = c.recv().unwrap();
    assert_eq!(k, kind::QUOTE);
    let rpk = Keys::load(&dir).unwrap().result_pk();
    let quote = Quote::open(&m, &rpk).expect("signed by the paired worker");
    assert_eq!((quote.nonce, quote.predicted_ttft_ms, quote.predicted_tpot_ms), ([5; 16], 200, 30));
    assert!(quote.meets(1_000, 50));
    // Execute under a capability bound to THIS session.
    let req = request(b"Explain ev:1\n[ev:1] CVE text");
    let mut e = |b: &mut [u8]| b.fill(3);
    let signed = signer.sign(&sign_req(&dir, c.binding, &req), 1_000, &mut e).unwrap();
    let capability = cap::open(&signed, &public_key(&DEVICE_SEED)).unwrap();
    exec(&mut c, &signed, &req);
    let (out, cap_id, seq, usage, hash, sig) = collect(&mut c).unwrap();
    assert_eq!(out, ANSWER.as_bytes());
    assert_eq!(cap_id, capability.capability_id);
    assert_eq!(hash, sha256(&[&out]));
    let msg = result_message(&cap_id, &capability.req.request_hash, &hash, seq, &usage);
    assert!(verify(&rpk, TAG_RESULT, &msg, &sig), "result signed by the paired worker key");
    // The device's own strict parser accepts what the worker produced.
    assert!(matches!(conductor_core::json::parse(&out), Ok(conductor_core::json::ModelOutput::Answer(_))));
    // The engine got the device-derived cache namespace, nothing the worker chose.
    let s = seen.lock().unwrap();
    assert_eq!(s[0].2, capability.cache_salt);
    drop(s);
    // Same capability again on the same session: replay.
    exec(&mut c, &signed, &req);
    assert!(collect(&mut c).unwrap_err().contains("REFUSE"));
    c.send(kind::BYE, &[]).unwrap();
    let st = h.join().unwrap();
    assert_eq!((st.jobs_ok, st.refused, st.quotes), (1, 1, 1));
}

#[test]
fn replay_refused_across_worker_restart_and_on_another_session() {
    let (dir, mut signer) = paired("restart");
    let req = request(b"hello");
    let mut e = |b: &mut [u8]| b.fill(4);
    // First worker process.
    let (addr, _, h) = spawn_worker(dir.clone(), vec![ANSWER], 1, 0);
    let mut c = connect(addr, &dir);
    let signed = signer.sign(&sign_req(&dir, c.binding, &req), 1_000, &mut e).unwrap();
    exec(&mut c, &signed, &req);
    collect(&mut c).unwrap();
    c.send(kind::BYE, &[]).unwrap();
    h.join().unwrap();
    assert_eq!(State::load(&dir).unwrap().high_water, 1, "mark persisted");
    // "Restarted" worker (fresh process state from disk), new session.
    let (addr, seen, h) = spawn_worker(dir.clone(), vec![ANSWER], 1, 0);
    let mut c2 = connect(addr, &dir);
    exec(&mut c2, &signed, &req); // captured capability: wrong session AND old counter
    assert!(collect(&mut c2).unwrap_err().contains("REFUSE"));
    // Even a FRESH capability for another session's binding is refused on this one.
    let other = signer.sign(&sign_req(&dir, [0xaa; 32], &req), 1_000, &mut e).unwrap();
    exec(&mut c2, &other, &req);
    assert!(collect(&mut c2).unwrap_err().contains("REFUSE"));
    // And a request that differs from the signed one.
    let good = signer.sign(&sign_req(&dir, c2.binding, &req), 1_000, &mut e).unwrap();
    exec(&mut c2, &good, &request(b"hellp"));
    assert!(collect(&mut c2).unwrap_err().contains("REFUSE"));
    assert!(seen.lock().unwrap().is_empty(), "the engine never saw a refused prompt");
    c2.send(kind::BYE, &[]).unwrap();
    h.join().unwrap();
}

#[test]
fn only_the_paired_device_can_open_a_channel() {
    let (dir, _) = paired("identity");
    let (addr, _, h) = spawn_worker(dir.clone(), vec![ANSWER], 2, 0);
    // A different device identity: the handshake fails at the worker.
    let stranger = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x12; 32]));
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert!(Chan::connect(s, &stranger, &worker_pub(&Keys::load(&dir).unwrap()), &mut OsEntropy).is_err());
    // Garbage instead of a handshake.
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&[9, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    let mut b = [0u8; 8];
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert!(matches!(s.read(&mut b), Ok(0) | Err(_)), "worker closes without answering");
    h.join().unwrap();
}

#[test]
fn kill_switch_and_limits() {
    let (dir, mut signer) = paired("kill");
    let long = format!(r#"{{"answer":{{"cites":["ev:1"],"summary":"{}"}}}}"#, "x".repeat(900));
    let (addr, _, h) = spawn_worker(dir.clone(), vec![long.as_str(), ANSWER, ANSWER], 1, 15);
    let mut c = connect(addr, &dir);
    let req = request(b"hello");
    let mut e = |b: &mut [u8]| b.fill(6);
    // Output larger than the capability allows: an ERROR frame, never a truncated answer.
    let small = SignRequest { max_response_bytes: 200, ..sign_req(&dir, c.binding, &req) };
    exec(&mut c, &signer.sign(&small, 1_000, &mut e).unwrap(), &req);
    assert_eq!(collect(&mut c).unwrap_err(), "ERROR 1");
    // Compute budget shorter than the engine needs: deadline error.
    let quick = SignRequest { max_compute_ms: 20, ..sign_req(&dir, c.binding, &req) };
    exec(&mut c, &signer.sign(&quick, 1_000, &mut e).unwrap(), &req);
    assert_eq!(collect(&mut c).unwrap_err(), "ERROR 2");
    // A capability issued before the kill switch…
    let old = signer.sign(&sign_req(&dir, c.binding, &req), 1_000, &mut e).unwrap();
    signer.bump_epoch();
    c.send(kind::EPOCH, &signer.announce_epoch(2_000).unwrap()).unwrap();
    assert_eq!(c.recv().unwrap().0, kind::EPOCH_OK);
    // …is dead, and the new epoch survives a restart.
    exec(&mut c, &old, &req);
    assert!(collect(&mut c).unwrap_err().contains("REFUSE"));
    c.send(kind::BYE, &[]).unwrap();
    h.join().unwrap();
    assert_eq!(State::load(&dir).unwrap().min_epoch, 2);
}

#[test]
fn pairing_detects_a_man_in_the_middle_and_saves_nothing() {
    let dir = tmp("mitm");
    Keys::generate(&dir).unwrap();
    let keys = Keys::load(&dir).unwrap();
    // The attacker relays but substitutes its own device keys toward the worker.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let dev = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        pairio::device_pair(&mut s, &[0x66; 32], &[0x67; 32], 1, [1; 16]).map(|d| d.code)
    });
    let (mut s, _) = l.accept().unwrap();
    let real_device_code = {
        // What the genuine device would show for ITS keys with the same nonces.
        let wd = conductor_core::pairing::worker_keys_digest(&keys.result_pk(), &keys.channel_blob());
        conductor_core::pairing::sas(&conductor_core::pairing::device_keys_digest(&public_key(&DEVICE_SEED), identity().pk.as_ref().try_into().unwrap()), &wd, &[1; 16], &[2; 16])
    };
    let r = pairio::worker_pair(&mut s, &keys, [2; 16], &mut |code| code == real_device_code);
    assert!(r.is_err(), "the codes differ, the owner does not confirm");
    let _ = dev.join();
    assert!(Paired::load(&dir).is_err(), "nothing saved");
    // Key files are private.
    use std::os::unix::fs::PermissionsExt;
    for f in [Keys::RESULT_FILE, Keys::NOISE_FILE] {
        assert_eq!(std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o077, 0);
    }
    std::fs::set_permissions(dir.join(Keys::RESULT_FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Keys::load(&dir).is_err(), "a world-readable key is refused");
}

#[test]
fn engine_must_be_loopback_and_speaks_openai_sse() {
    assert!(OpenAiCompat::new("http://192.168.1.50:8080", "m").is_err());
    assert!(OpenAiCompat::new("https://127.0.0.1:8080", "m").is_err());
    assert!(OpenAiCompat::new("http://example.com:80", "m").is_err());
    assert!(OpenAiCompat::new("http://[::1]:8080/v", "m").is_ok());
    // A fake llama-server / vLLM on loopback: chunked SSE.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = vec![0u8; 16384];
        let mut got = Vec::new();
        loop {
            let n = s.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
            if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..i]).to_lowercase();
                let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                if got.len() >= i + 4 + len {
                    got.drain(..i + 4);
                    break;
                }
            }
        }
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        for piece in ["{\"answer\":{\"cites\":[\"ev:1\"],", "\"summary\":\"ok\"}}"] {
            let ev = format!("data: {}\n\n", serde_json::json!({"choices":[{"delta":{"content":piece}}]}));
            s.write_all(format!("{:x}\r\n{ev}\r\n", ev.len()).as_bytes()).unwrap();
        }
        let done = "data: [DONE]\n\n";
        s.write_all(format!("{:x}\r\n{done}\r\n0\r\n\r\n", done.len()).as_bytes()).unwrap();
        serde_json::from_slice::<serde_json::Value>(&got).unwrap()
    });
    let mut e = OpenAiCompat::new(&format!("http://127.0.0.1:{port}"), "qwen").unwrap();
    let mut out = Vec::new();
    let g = GenRequest { prompt: "p", max_out_bytes: 4096, max_out_units: 300, deadline: Instant::now() + Duration::from_secs(5), cache_scope: cap::cache_scope::SESSION, cache_salt: [0xab; 32], offload_hints: 0 };
    let st = e.generate(&g, &mut |p| {
        out.extend_from_slice(p);
        true
    })
    .unwrap();
    assert_eq!(st.pieces, 2);
    assert!(matches!(conductor_core::json::parse(&out), Ok(conductor_core::json::ModelOutput::Answer(_))));
    let body = srv.join().unwrap();
    assert_eq!(body["cache_salt"], "ab".repeat(32), "session reuse only inside the device's namespace");
    assert_eq!(body["temperature"], 0);
    assert_eq!(body["response_format"]["type"], "json_schema");
    // No reuse allowed → a salt nobody else can ever match.
    let g2 = GenRequest { cache_scope: 0, ..g };
    let b1: serde_json::Value = serde_json::from_slice(&e.request_body(&g2)).unwrap();
    let b2: serde_json::Value = serde_json::from_slice(&e.request_body(&g2)).unwrap();
    assert_ne!(b1["cache_salt"], b2["cache_salt"]);
    assert_eq!(b1["cache_prompt"], false);
}
