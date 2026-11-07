//! A2 (M5.5) — a REAL `wasm32-wasip1` detection module (std, stdin/stdout — the SAME shape
//! as the production signed modules napse-dpi/dnsxai/qsecbit). It reads an L4 header from
//! STDIN, classifies the big-endian dst-port at bytes [2..4] (mirrors the in-kernel
//! rules.rs THREAT_RULE / the M5.4 detection corpus: 4444/23/31337 => DROP), and writes a
//! ONE-byte verdict to STDOUT (1 = PASS, 2 = DROP). This is the guest the EL0 wasip1 host
//! runs THROUGH wasmi to prove the real WASI preview1 stdin/stdout ABI on heqk (vs the
//! earlier bespoke hp_input/hp_emit shim).
use std::io::{Read, Write};

fn is_threat(port: u16) -> bool {
    port == 4444 || port == 23 || port == 31337
}

fn main() {
    let mut hdr = [0u8; 16];
    // A single read is enough for the fixed 16-byte L4 header the host feeds on stdin.
    let n = std::io::stdin().read(&mut hdr).unwrap_or(0);
    let port: u16 = if n >= 4 {
        ((hdr[2] as u16) << 8) | hdr[3] as u16
    } else {
        0
    };
    let verdict: u8 = if is_threat(port) { 2 } else { 1 };
    let _ = std::io::stdout().write_all(&[verdict]);
    let _ = std::io::stdout().flush();
}
