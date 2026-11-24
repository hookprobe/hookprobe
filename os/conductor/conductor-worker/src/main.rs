// SPDX-License-Identifier: AGPL-3.0-only
//! conductor-worker — the HookProbe Conductor reference worker for the owner's GPU box.
//!
//!   conductor-worker keygen    --dir D
//!   conductor-worker show      --dir D
//!   conductor-worker pair      --dir D --listen IP:PORT [--code NNNNNN]
//!   conductor-worker calibrate --dir D --engine URL --model NAME --offload N
//!   conductor-worker run       --dir D --listen IP:PORT --engine URL --model NAME
//!                              [--idle-cmd "PROG ARGS…"] [--trust-clock]
//!
//! Hardening:
//! - refuses to run as root;
//! - listens on one named interface address only (the compute segment), never 0.0.0.0 / ::;
//! - talks to the engine on loopback only (the engine must not be reachable from the network);
//! - serves exactly one paired device over heqk's PQ-hybrid Noise channel;
//! - pairing needs the owner to type the six-digit code shown in Mission Control;
//! - logs ids, hashes, sizes and timings, never prompts or outputs.

use conductor_worker::chan::Chan;
use conductor_worker::engine::{Engine, GenRequest, OpenAiCompat};
use conductor_worker::entropy::{EntropySource, OsEntropy};
use conductor_worker::files::{hex, Keys};
use conductor_worker::quote::{IdleProbe, Profile};
use conductor_worker::serve::{system_ms, Worker};
use std::io::{BufRead, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}
fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
fn need(args: &[String], name: &str) -> Result<String, String> {
    arg(args, name).ok_or_else(|| format!("missing {name}"))
}

fn refuse_root() -> Result<(), String> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return Err("refusing to run as root: create an unprivileged user (see deploy/conductor-worker.service)".into());
    }
    Ok(())
}

fn listen_addr(args: &[String]) -> Result<SocketAddr, String> {
    let a: SocketAddr = need(args, "--listen")?.parse().map_err(|_| "--listen must be IP:PORT")?;
    if a.ip().is_unspecified() {
        return Err("refusing to listen on all interfaces: give the compute-segment address".into());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args),
        Some("show") => show(&args),
        Some("pair") => pair(&args),
        Some("calibrate") => calibrate(&args),
        Some("run") => run(&args),
        _ => Err("usage: conductor-worker keygen|show|pair|calibrate|run --dir D … (see the file header)".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("conductor-worker: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dir(args: &[String]) -> Result<PathBuf, String> {
    Ok(PathBuf::from(need(args, "--dir")?))
}

fn keygen(args: &[String]) -> Result<(), String> {
    refuse_root()?;
    let d = dir(args)?;
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Keys::generate(&d)?;
    show(args)
}

fn show(args: &[String]) -> Result<(), String> {
    let keys = Keys::load(&dir(args)?)?;
    println!("result_pk      {}", hex(&keys.result_pk()));
    println!("channel_static {}", hex(&keys.channel_blob()));
    Ok(())
}

fn pair(args: &[String]) -> Result<(), String> {
    refuse_root()?;
    let d = dir(args)?;
    let keys = Keys::load(&d)?;
    let l = TcpListener::bind(listen_addr(args)?).map_err(|e| e.to_string())?;
    eprintln!("waiting for the device's pairing request on {} (start pairing in Mission Control)…", l.local_addr().map_err(|e| e.to_string())?);
    let (mut s, peer) = l.accept().map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(120))).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 16];
    OsEntropy.fill(&mut nonce).map_err(|_| "no entropy")?;
    let typed = arg(args, "--code");
    let mut confirm = |code: u32| -> bool {
        eprintln!("pairing request from {peer}");
        let entered = match &typed {
            Some(t) => t.clone(),
            None => {
                eprint!("Type the 6-digit code shown in Mission Control: ");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                let _ = std::io::stdin().lock().read_line(&mut line);
                line
            }
        };
        let ok = entered.trim() == format!("{code:06}");
        if !ok {
            eprintln!("the codes differ: someone may be in the middle. Nothing was saved.");
        }
        ok
    };
    let w = conductor_worker::pairio::worker_pair(&mut s, &keys, nonce, &mut confirm)?;
    w.paired.save(&d)?;
    eprintln!("paired with device {} (tier P{}); confirm in Mission Control to finish.", hex(&w.paired.channel_identity_pk[..8]), w.paired.tier);
    Ok(())
}

fn calibrate(args: &[String]) -> Result<(), String> {
    refuse_root()?;
    let d = dir(args)?;
    let mut e = OpenAiCompat::new(&need(args, "--engine")?, &need(args, "--model")?).map_err(|e| format!("{e:?}"))?;
    let offload: u8 = need(args, "--offload")?.parse().map_err(|_| "--offload: 1 all-in-VRAM, 2 experts-in-RAM, 3 NVMe streaming, 4 CPU only")?;
    let mut run = |prompt: &str| -> Result<conductor_worker::engine::GenStats, String> {
        let g = GenRequest {
            prompt,
            max_out_bytes: 4096,
            max_out_units: 256,
            deadline: Instant::now() + Duration::from_secs(300),
            cache_scope: 0,
            cache_salt: [0; 32],
            offload_hints: 0,
        };
        e.generate(&g, &mut |_| true).map_err(|e| format!("{e:?}"))
    };
    let small = "Reply with a JSON answer citing ev:1 and a one-sentence summary.\n[ev:1] Port scan from 198.51.100.7.";
    let big = format!("{small}\n{}", "[ev:2] repeated connection attempt observed on tcp/443.\n".repeat(70));
    let a = run(small)?;
    let b = run(&big)?;
    let units_diff = conductor_core::limits::units(big.len()).saturating_sub(conductor_core::limits::units(small.len())).max(1);
    let per_k = (u64::from(b.ttft_ms.saturating_sub(a.ttft_ms)) * 1000 / u64::from(units_diff)) as u32;
    let tpot = if a.pieces > 1 { a.total_ms.saturating_sub(a.ttft_ms) / (a.pieces - 1) } else { a.total_ms };
    let p = Profile { offload, ttft_base_ms: a.ttft_ms, ttft_per_kunit_ms: per_k, tpot_ms: tpot.max(1) };
    p.save(&d)?;
    println!("{p:?}");
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    refuse_root()?;
    let d = dir(args)?;
    let engine = OpenAiCompat::new(&need(args, "--engine")?, &need(args, "--model")?).map_err(|e| format!("engine: {e:?} (it must be http://127.0.0.1:PORT or [::1])"))?;
    let idle = IdleProbe { cmd: arg(args, "--idle-cmd").map(|c| c.split_whitespace().map(String::from).collect()), timeout: Duration::from_secs(2) };
    let mut w = Worker::open(d, engine, idle)?;
    if flag(args, "--trust-clock") {
        w.wall_clock = Some(system_ms);
    }
    let l = TcpListener::bind(listen_addr(args)?).map_err(|e| e.to_string())?;
    eprintln!(
        "[conductor-worker] serving device {} as P{} on {} with {}",
        hex(&w.paired.channel_identity_pk[..8]),
        w.paired.tier,
        l.local_addr().map_err(|e| e.to_string())?,
        w.engine.name()
    );
    let resp = Keys::load(&w.dir)?.noise;
    let identity = w.paired.channel_identity_pk;
    for s in l.incoming() {
        let Ok(s) = s else { continue };
        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
        match Chan::accept(s, &resp, &identity, &mut OsEntropy) {
            Ok(mut c) => w.serve(&mut c),
            Err(e) => eprintln!("[conductor-worker] handshake refused: {e}"),
        }
    }
    Ok(())
}
