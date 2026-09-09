//! heqk MSSP responder-sim (HOST / std).
//!
//! Metal-proves the M4.2b PQ-hybrid Noise handshake against a real CM5 heqk device by
//! playing the enrollment RESPONDER (the MSSP) over the wire. It links the kernel's EXACT
//! `securechannel.rs` (via `#[path]`), so every byte on the wire is produced by the same
//! code the device runs — no second implementation to drift.
//!
//! Two modes:
//!   responder-sim --selftest            in-process initiator<->responder cross-check (no HW):
//!                                        proves the linked crypto + chunk transport agree.
//!   responder-sim --live [--dev-ip IP] [--dev-id N]
//!                                        bind UDP :7654, reassemble the device's broadcast
//!                                        msg1, answer msg2 unicast; print Established + keys.
//!
//! The responder STATIC keypair is derived from the SAME provisioning seeds whose PUBLIC half
//! is baked into the device image (kernel testdata/provisioned_mssp_pub.bin), so the device
//! authenticates this responder. The device's ed25519 identity is derived from `device_id`
//! (0 when there is no seal-handoff, i.e. the netmetal image) — override with --dev-id.

mod entropy;

// The kernel secure-channel module, verbatim. `crate::entropy` inside it resolves to the
// shim above; `boot_abi` + the RustCrypto crates resolve to this crate's deps.
#[path = "../../heqk/kernel/src/securechannel.rs"]
mod securechannel;

use boot_abi::sha256;
use ed25519_compact::{KeyPair, PublicKey as EdPub, Seed};
use entropy::OsEntropy;
use securechannel::{
    hs_chunk, initiator_read_msg2, initiator_write_msg1, responder_read_msg1, responder_write_msg2, HsReasm,
    InitiatorRandomness, ResponderPub, ResponderRandomness, ResponderStatic,
};
use std::net::UdpSocket;

const HS_PORT: u16 = 7654;
const TENANT: &[u8] = b"TENANT42";

/// The MSSP responder static keypair — from the SAME seeds as
/// controlplane::dump_provisioned_blob, so `.public()` == the device's baked MSSP pubkey.
fn responder_static() -> ResponderStatic {
    ResponderStatic::from_seeds(
        &sha256::digest(b"HEQK-DEV-PROV-mssp-x25519"),
        &sha256::digest(b"HEQK-DEV-PROV-mssp-mlkem-d"),
        &sha256::digest(b"HEQK-DEV-PROV-mssp-mlkem-z"),
    )
}

/// The device's ed25519 identity public key = KeyPair::from_seed(sha256(device_id_le)).
fn device_pk(device_id: u64) -> EdPub {
    KeyPair::from_seed(Seed::new(sha256::digest(&device_id.to_le_bytes()))).pk
}

fn print_pub_hex(label: &str, resp_pub: &ResponderPub) {
    print!("{label} x_pk=");
    for b in resp_pub.x_pk().iter() {
        print!("{b:02x}");
    }
    print!(" k_ek[0..8]=");
    for b in resp_pub.k_ek_bytes().iter().take(8) {
        print!("{b:02x}");
    }
    println!(" (k_ek {} B)", resp_pub.k_ek_bytes().len());
}

/// In-process initiator<->responder cross-check: proves the linked securechannel produces a
/// mutually-consistent handshake AND that hs_chunk/HsReasm round-trips the >MTU msg1. This is
/// the host equivalent of the kernel's [P19-controlplane] gate — run it before flashing.
fn selftest() -> bool {
    let resp = responder_static();
    let resp_pub = resp.public();
    let dev_id = 0u64;
    let dev_kp = KeyPair::from_seed(Seed::new(sha256::digest(&dev_id.to_le_bytes())));
    let dev_pk = dev_kp.pk;
    print_pub_hex(" [sim] responder MSSP pub:", &resp_pub);

    let mut ent = OsEntropy;
    let irand = match InitiatorRandomness::from_entropy(&mut ent) {
        Ok(r) => r,
        Err(_) => return fail("initiator randomness"),
    };
    let rrand = match ResponderRandomness::from_entropy(&mut ent) {
        Ok(r) => r,
        Err(_) => return fail("responder randomness"),
    };

    // (1) initiator writes msg1.
    let (msg1, ipend) = match initiator_write_msg1(&dev_kp, &resp_pub, &irand, b"heqk-enroll-msg1") {
        Some(x) => x,
        None => return fail("initiator_write_msg1"),
    };

    // (2) round-trip msg1 THROUGH the chunk transport (as it travels on the wire).
    let mut reasm = HsReasm::new();
    let mut complete = false;
    let ok_chunk = hs_chunk(msg1.as_slice(), |framed| match reasm.feed(framed) {
        Ok(Some(_)) => {
            complete = true;
            true
        }
        Ok(None) => true,
        Err(_) => false,
    });
    if !ok_chunk || !complete {
        return fail("hs_chunk/HsReasm msg1 round-trip");
    }
    if reasm.message() != msg1.as_slice() {
        return fail("reassembled msg1 != original");
    }

    // (3) responder authenticates the device + writes msg2.
    let rpend = match responder_read_msg1(&resp, &dev_pk, reasm.message()) {
        Ok(p) => p,
        Err(e) => return fail(&format!("responder_read_msg1: {e:?}")),
    };
    let (msg2, rsession) = match responder_write_msg2(rpend, &rrand, TENANT) {
        Some(x) => x,
        None => return fail("responder_write_msg2"),
    };

    // (4) initiator reads msg2 -> Session.
    let (isession, _rec) = match initiator_read_msg2(ipend, msg2.as_slice()) {
        Ok(x) => x,
        Err(e) => return fail(&format!("initiator_read_msg2: {e:?}")),
    };

    // (5) crossed keys must match (initiator.send == responder.recv, and vice-versa).
    let keys_ok = isession.send.key_for_test() == rsession.recv.key_for_test()
        && isession.recv.key_for_test() == rsession.send.key_for_test();
    if !keys_ok {
        return fail("crossed session keys mismatch");
    }

    println!(" [sim] SELFTEST PASS — full PQ-hybrid handshake + chunk transport agree; crossed keys match.");
    true
}

fn fail(what: &str) -> bool {
    eprintln!(" [sim] SELFTEST FAIL — {what}");
    false
}

/// Live responder: bind UDP :7654, reassemble the device's broadcast msg1, answer msg2
/// unicast to `dev_ip`, print Established. Loops so repeated device attempts are all served.
fn run_live(dev_ip: &str, dev_id: u64) -> std::io::Result<()> {
    let resp = responder_static();
    print_pub_hex(" [sim] responder MSSP pub:", &resp.public());
    let dev_pk = device_pk(dev_id);
    let dpk_bytes: &[u8] = dev_pk.as_ref();
    println!(" [sim] device_id={dev_id} → authenticating device ed25519 pk (first 8 bytes) {:02x?}",
        &dpk_bytes[..8]);

    let sock = UdpSocket::bind(("0.0.0.0", HS_PORT))?;
    sock.set_broadcast(true)?;
    println!(" [sim] listening on 0.0.0.0:{HS_PORT} (broadcast); will answer msg2 to {dev_ip}:{HS_PORT}");

    let mut reasm = HsReasm::new();
    let mut buf = [0u8; 2048];
    let mut handshakes = 0u32;
    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        // The device also broadcasts a 90 B presence BEACON on :7654 whose UDP payload starts
        // with "HEQK-ENROLL-HELO". It is NOT a handshake chunk — feeding it to HsReasm corrupts
        // an in-progress msg1 reassembly. Skip it.
        if buf[..n].starts_with(b"HEQK-ENROLL") {
            continue;
        }
        match reasm.feed(&buf[..n]) {
            Ok(Some(total)) => {
                println!(" [sim] msg1 reassembled ({total} B) from {from}");
                let mut ent = OsEntropy;
                let rrand = match ResponderRandomness::from_entropy(&mut ent) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(" [sim] entropy error: {e:?}");
                        reasm = HsReasm::new();
                        continue;
                    }
                };
                match responder_read_msg1(&resp, &dev_pk, reasm.message()) {
                    Ok(rpend) => match responder_write_msg2(rpend, &rrand, TENANT) {
                        Some((msg2, rsession)) => {
                            let sent = hs_chunk(msg2.as_slice(), |framed| {
                                sock.send_to(framed, (dev_ip, HS_PORT)).is_ok()
                            });
                            handshakes += 1;
                            println!(
                                " [sim] ✅ msg2 sent (chunks_ok={sent}); ESTABLISHED #{handshakes}; \
                                 responder send-key[0..8]={:02x?}",
                                &rsession.send.key_for_test()[..8]
                            );
                        }
                        None => eprintln!(" [sim] responder_write_msg2 failed"),
                    },
                    Err(e) => eprintln!(" [sim] responder_read_msg1 rejected the device: {e:?} \
                        (dev-id/pubkey mismatch? try --dev-id from the device's serial log)"),
                }
                reasm = HsReasm::new();
            }
            Ok(None) => { /* more chunks needed */ }
            Err(_) => {
                eprintln!(" [sim] reassembly error — resetting");
                reasm = HsReasm::new();
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("--selftest");
    let arg_val = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
    };
    match mode {
        "--selftest" => {
            std::process::exit(if selftest() { 0 } else { 1 });
        }
        "--live" => {
            let dev_ip = arg_val("--dev-ip").unwrap_or_else(|| "10.200.0.2".to_string());
            // --dev-id accepts decimal or 0x-hex (the device prints its OTP id as 0x… on serial).
            let dev_id = arg_val("--dev-id")
                .and_then(|s| {
                    let s = s.trim();
                    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        Some(h) => u64::from_str_radix(h, 16).ok(),
                        None => s.parse().ok(),
                    }
                })
                .unwrap_or(0u64);
            if let Err(e) = run_live(&dev_ip, dev_id) {
                eprintln!(" [sim] fatal: {e}");
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("usage: responder-sim [--selftest | --live [--dev-ip IP] [--dev-id N]]");
            eprintln!("  unknown mode: {other}");
            std::process::exit(2);
        }
    }
}
