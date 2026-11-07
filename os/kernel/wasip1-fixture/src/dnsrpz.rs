//! A2+ (M5.5 catalogue) — a SECOND, genuinely-distinct REAL `wasm32-wasip1` detection
//! module: a DNS-RPZ sinkhole detector. It reads a dotted lowercase DNS query NAME from
//! STDIN (e.g. b"ads.tracker" or b"host.malware.example"), and DROPs it (verdict 2, i.e.
//! "sinkhole") iff the name matches the RPZ blocklist by the SAME rule the in-kernel
//! dnssink::rpz_blocked uses — an EXACT match, or a subdomain (name ends with ".<blocked>"
//! on a label boundary) — else PASS (verdict 1). Together with the port-signature module
//! this makes a 2-module signed CATALOGUE run through the one EL0 wasip1 host, each doing
//! DIFFERENT real detection at parity with a distinct in-kernel reference (rules::run_l4 /
//! dnssink::rpz_blocked) — the portable-signed-rule product thesis, on the real WASI ABI.
use std::io::{Read, Write};

/// == kernel dnssink::RPZ_LIST.
const RPZ: &[&[u8]] = &[b"malware.example", b"ads.tracker", b"c2.evil.test"];

/// == kernel dnssink::rpz_blocked: exact match OR a label-boundary subdomain.
fn blocked(name: &[u8]) -> bool {
    for &b in RPZ {
        if name == b {
            return true;
        }
        if name.len() > b.len() + 1 {
            let start = name.len() - b.len();
            if &name[start..] == b && name[start - 1] == b'.' {
                return true;
            }
        }
    }
    false
}

fn main() {
    let mut buf = [0u8; 256];
    let n = std::io::stdin().read(&mut buf).unwrap_or(0);
    let name = &buf[..n];
    let verdict: u8 = if blocked(name) { 2 } else { 1 }; // 2 = DROP/sinkhole, 1 = PASS
    let _ = std::io::stdout().write_all(&[verdict]);
    let _ = std::io::stdout().flush();
}
