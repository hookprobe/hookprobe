//! WASI entry point for the QSECBIT detection module.
//!
//! ## Protocol
//!
//! The supervisor starts this binary under Wasmtime with the grants declared in
//! `module.yaml`:
//! - `read: /var/lib/hookprobe/events` — Senzorium writes normalized telemetry
//!   events here; this process tails the file via stdin redirection.
//! - `wasi-nn: cpu` — reserved for the WASI-NN upgrade path.
//!
//! **Input** (one telemetry tick per line, comma-separated floats):
//! ```text
//! # cpu_norm,memory_norm,network_norm,disk_io_norm
//! # optionally appended: ,p_attack (ML score, 0.0 default)
//! 0.12,0.21,0.16,0.34
//! 0.90,0.01,0.01,0.01,0.0
//! # comment lines and blank lines are ignored
//! ```
//!
//! All four required values are normalized to `[0.0, 1.0]`.
//! The optional 5th field `p_attack` accepts the ML classifier output once
//! the WASI-NN upgrade path is implemented.
//!
//! **Output** (one JSON object per line, written to stdout, consumed by Senzorium
//! and surfaced in the Mission Control "QSecBit breakdown" panel):
//! ```json
//! {"score":0.0143,"band":"GREEN","drift":0.0018,"qdrift":0.0690,"p_attack":0.0000,"decay":0.0000,"maha_dist":0.1871,"entropy_nats":1.3102}
//! {"score":0.5000,"band":"AMBER","drift":1.0000,"qdrift":1.0000,"p_attack":0.0000,"decay":0.0000,"maha_dist":6.3171,"entropy_nats":0.1780}
//! ```
//!
//! JSON fields:
//! - `score`         — composite risk R ∈ [0, 1]; lower = healthier
//! - `band`          — "GREEN" | "AMBER" | "RED" (RAG status)
//! - `drift`         — normalized Mahalanobis component (α-weighted)
//! - `qdrift`        — normalized entropy-deviation component (δ-weighted)
//! - `p_attack`      — ML attack probability (β-weighted; 0.0 until WASI-NN)
//! - `decay`         — classifier confidence decay (γ-weighted; 0.0 on first tick)
//! - `maha_dist`     — raw Mahalanobis distance (for display / debugging)
//! - `entropy_nats`  — Shannon entropy of the telemetry vector (nats)
//!
//! **Stderr** receives error diagnostics (supervisor may redirect to the log).
//!
//! ## TODO(wasi-nn)
//!
//! When the ONNX model is available (V1's `ml/classifier.py` exported via
//! `sklearn2pmml` or similar), enable the WASI-NN path:
//! ```ignore
//! // Load the model once at startup:
//! // let graph = wasi_nn::GraphBuilder::new(wasi_nn::GraphEncoding::Onnx,
//! //     wasi_nn::ExecutionTarget::CPU)
//! //     .build_from_files(["/var/lib/hookprobe/models/qsecbit.onnx"])
//! //     .expect("load ONNX model");
//! // let ctx = graph.init_execution_context().expect("init ctx");
//! //
//! // Per tick: feed the feature vector, read p_attack from output:
//! // let feats = [cpu_norm as f32, memory_norm as f32, ...];
//! // ctx.set_input(0, wasi_nn::TensorType::F32, &[1, feats.len()], &feats)?;
//! // ctx.compute()?;
//! // let mut logits = vec![0f32; 2]; // binary attack/benign
//! // ctx.get_output(0, &mut logits)?;
//! // let p_attack = (logits[1] as f64).clamp(0.0, 1.0); // attack class probability
//! ```
//! Then pass `p_attack` in the `QsecbitInput` instead of `0.0`.

use qsecbit::{compute, QsecbitConfig, QsecbitInput};
use std::io::{self, BufRead, Write};

fn main() {
    let cfg = QsecbitConfig::default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::LineWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[qsecbit] stdin read error: {e}");
                break;
            }
        };
        let trimmed = line.trim();

        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse comma-separated floats.
        // Required: cpu_norm,memory_norm,network_norm,disk_io_norm
        // Optional 5th: p_attack (default 0.0)
        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.len() < 4 {
            eprintln!("[qsecbit] expected ≥4 comma-separated floats, got: {trimmed:?}");
            continue;
        }

        let parsed: Vec<f64> = parts
            .iter()
            .map(|s| s.trim().parse::<f64>().unwrap_or(f64::NAN))
            .collect();

        if parsed.iter().any(|v| v.is_nan()) {
            eprintln!("[qsecbit] non-numeric field in: {trimmed:?}");
            continue;
        }

        let mut input = QsecbitInput::from_telemetry(parsed[0], parsed[1], parsed[2], parsed[3]);
        if parts.len() >= 5 {
            input.p_attack = parsed[4].clamp(0.0, 1.0);
        }

        let result = compute(&input, &cfg);
        let bd = &result.breakdown;

        // Hand-crafted JSON — zero dependencies, minimal allocations.
        // Mirrors V1 QsecbitSample.to_dict() field names where they overlap.
        let json = format!(
            concat!(
                r#"{{"score":{score:.4},"band":"{band}","#,
                r#""drift":{drift:.4},"qdrift":{qdrift:.4},"#,
                r#""p_attack":{p:.4},"decay":{decay:.4},"#,
                r#""maha_dist":{maha:.4},"entropy_nats":{ent:.4}}}"#,
            ),
            score = result.score,
            band  = result.band.as_str(),
            drift = bd.mahalanobis_drift,
            qdrift = bd.entropy_deviation,
            p     = bd.attack_probability,
            decay = bd.classifier_decay,
            maha  = bd.raw_mahalanobis_distance,
            ent   = bd.telemetry_entropy_nats,
        );

        if let Err(e) = writeln!(out, "{json}") {
            eprintln!("[qsecbit] stdout write error: {e}");
            break;
        }
        // TA1 (2026-07-17): flush per score. Continuous service (`tail -F telemetry | qsecbit >>
        // qsecbit-scores`); a LineWriter over WASI stdout doesn't reliably flush on newline in the
        // wasm streaming context. qsecbit's ~5 s cadence usually filled the buffer so it *looked*
        // fine, but the scores were delivered late/in bursts and a low-telemetry device could starve.
        // Same fix napse/aegis-guard/dnsxai carry.
        if let Err(e) = out.flush() {
            eprintln!("[qsecbit] stdout flush error: {e}");
            break;
        }
    }
}
