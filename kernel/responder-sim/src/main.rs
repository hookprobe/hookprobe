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

// --- M4.5 segmentation authority (the reach policy the sim serves post-Established) ----------
// The device requests its policy with this opcode (enroll.rs REACH_POLICY_REQ).
const REACH_POLICY_REQ: &[u8] = b"HEQK-SEG-GET";
// The reach tenant the device is enrolled under (must equal the device-baked Enrollment.tenant_id).
const SEG_TENANT: u64 = 0x5445_4E41; // "TENA"
// ReachPolicy wire layout — mirrors kernel enroll.rs::ReachPolicy EXACTLY (fail-closed parsed
// on-device, so any drift is rejected, never mis-applied).
const RP_MAGIC: u32 = 0x314C_5052; // "RPL1" LE
const RP_DEV_SLOTS: usize = 64; // segment::DEV_SLOTS
const RP_HDR_LEN: usize = 32;
const RP_ENTRY_LEN: usize = 8;
const RP_BODY_LEN: usize = RP_HDR_LEN + RP_DEV_SLOTS * RP_ENTRY_LEN; // 544
const RP_WIRE_LEN: usize = RP_BODY_LEN + 64; // + Ed25519 sig = 608
// Reach codes (segment::Reach::to_code): Full=0, InternetOnly=1, Quarantine=2.
const REACH_QUARANTINE: u8 = 2;
const REACH_INTERNET_ONLY: u8 = 1;

/// The operator Ed25519 signing keypair — the INDEPENDENT trust root (C9), from the same public
/// dev seed the device pins (enroll.rs seg_policy_selftest). In production this private key lives
/// only with the operator; here it is a shared dev key so the metal bring-up is reproducible.
fn operator_keypair() -> ed25519_compact::KeyPair {
    ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(sha256::digest(
        b"HEQK-M4.5-operator-signing-key",
    )))
}

/// Build + operator-sign a 2-entry reach policy FOR `device_fp` (sig covers body ‖ device_fp, C14).
/// Byte-identical layout to kernel enroll.rs::build_signed_policy: MAC byte0 differs (0x02 vs 0x0a)
/// so the two entries land in distinct reach-table slots. Returns the WIRE_LEN record.
fn build_signed_policy(gen: u64, tenant: u64, device_fp: &[u8; 32]) -> [u8; RP_WIRE_LEN] {
    let mut b = [0u8; RP_WIRE_LEN];
    // header
    b[0..4].copy_from_slice(&RP_MAGIC.to_le_bytes());
    b[4] = 1; // VERSION
    b[5] = 0; // flags
    b[6..8].copy_from_slice(&2u16.to_le_bytes()); // entry_count
    b[8..16].copy_from_slice(&gen.to_le_bytes());
    b[16..24].copy_from_slice(&tenant.to_le_bytes());
    b[24..28].copy_from_slice(&0x0A00_0001u32.to_le_bytes()); // infra_gw 10.0.0.1
    b[28..32].copy_from_slice(&0x0A00_0002u32.to_le_bytes()); // infra_dns 10.0.0.2
    // entry 0: MAC 02:..:10 -> Quarantine
    let e0 = RP_HDR_LEN;
    b[e0..e0 + 6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
    b[e0 + 6] = REACH_QUARANTINE;
    // entry 1: MAC 0a:..:11 -> InternetOnly
    let e1 = RP_HDR_LEN + RP_ENTRY_LEN;
    b[e1..e1 + 6].copy_from_slice(&[0x0a, 0, 0, 0, 0, 0x11]);
    b[e1 + 6] = REACH_INTERNET_ONLY;
    // sign body ‖ device_fp
    let mut sig_msg = [0u8; RP_BODY_LEN + 32];
    sig_msg[..RP_BODY_LEN].copy_from_slice(&b[..RP_BODY_LEN]);
    sig_msg[RP_BODY_LEN..].copy_from_slice(device_fp);
    let kp = operator_keypair();
    let sig = kp.sk.sign(&sig_msg[..], None);
    b[RP_BODY_LEN..].copy_from_slice(&sig[..]);
    b
}

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
fn run_live(dev_ip: &str, dev_id: u64, gen: u64) -> std::io::Result<()> {
    let resp = responder_static();
    print_pub_hex(" [sim] responder MSSP pub:", &resp.public());
    let dev_pk = device_pk(dev_id);
    let dpk_bytes: &[u8] = dev_pk.as_ref();
    println!(" [sim] device_id={dev_id} → authenticating device ed25519 pk (first 8 bytes) {:02x?}",
        &dpk_bytes[..8]);

    let op_kp = operator_keypair();
    let op_pk: &[u8] = op_kp.pk.as_ref();
    println!(" [sim] operator signing pubkey (bake into device as OPERATOR_PK): {}",
        op_pk.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let sock = UdpSocket::bind(("0.0.0.0", HS_PORT))?;
    sock.set_broadcast(true)?;
    println!(" [sim] listening on 0.0.0.0:{HS_PORT} (broadcast); will answer msg2 + serve ReachPolicy to {dev_ip}:{HS_PORT}");

    let mut reasm = HsReasm::new();
    let mut buf = [0u8; 2048];
    // Some(session, device_fp) once Established: the next non-beacon datagram is the encrypted
    // REACH_POLICY_REQ, which we answer with the operator-signed policy over the same Session.
    let mut established: Option<(securechannel::Session, [u8; 32])> = None;
    let mut handshakes = 0u32;
    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        // Skip the 90 B presence beacon (UDP payload starts "HEQK-ENROLL-HELO").
        if buf[..n].starts_with(b"HEQK-ENROLL") {
            continue;
        }

        // POLICY phase — Established: decrypt the REQ over the Session, serve the signed policy.
        if established.is_some() {
            let mut reqpt = [0u8; 64];
            let decoded = established
                .as_mut()
                .and_then(|(s, _)| s.recv.decrypt_into(b"", &buf[..n], &mut reqpt).ok())
                .map(|got| &reqpt[..got] == REACH_POLICY_REQ);
            match decoded {
                Some(true) => {
                    let (session, device_fp) = established.as_mut().unwrap();
                    let pol = build_signed_policy(gen, SEG_TENANT, device_fp);
                    let mut rec = [0u8; RP_WIRE_LEN + 16];
                    match session.send.encrypt_into(b"", &pol, &mut rec) {
                        Some(rl) => {
                            let ok = sock.send_to(&rec[..rl], (dev_ip, HS_PORT)).is_ok();
                            println!(" [sim] ✅ REQ received; operator-signed ReachPolicy sent (gen={gen} tenant=TENA, MAC 02..10=Quarantine, 0a..11=InternetOnly; {RP_WIRE_LEN} B plaintext → {rl} B record, sent_ok={ok}) — device should verify+ARM");
                        }
                        None => eprintln!(" [sim] policy encrypt failed"),
                    }
                    established = None; // one policy per session; a device reboot re-handshakes
                    reasm = HsReasm::new();
                    continue;
                }
                Some(false) => {
                    // Decrypted on this Session but not the REQ opcode — ignore, stay Established.
                    continue;
                }
                None => {
                    // NOT decryptable on this Session → a NEW handshake attempt (e.g. the prior
                    // session half-completed: we Established but the device did not). RECOVER:
                    // drop the stale session + fall through to handshake processing of THIS frame.
                    println!(" [sim] stale session — new handshake attempt detected, resetting");
                    established = None;
                    reasm = HsReasm::new();
                }
            }
        }

        // HANDSHAKE phase.
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
                    Ok(rpend) => {
                        // The device sends device_fp (= sha256(dev.pk)) as msg1 payload1 — capture
                        // it BEFORE responder_write_msg2 consumes rpend, to sign the policy for it.
                        let mut device_fp = [0u8; 32];
                        let pl = rpend.payload1.as_slice();
                        if pl.len() == 32 {
                            device_fp.copy_from_slice(pl);
                        }
                        match responder_write_msg2(rpend, &rrand, TENANT) {
                            Some((msg2, rsession)) => {
                                let sent = hs_chunk(msg2.as_slice(), |framed| {
                                    sock.send_to(framed, (dev_ip, HS_PORT)).is_ok()
                                });
                                handshakes += 1;
                                println!(
                                    " [sim] ✅ msg2 sent (chunks_ok={sent}); ESTABLISHED #{handshakes}; \
                                     device_fp[0..8]={:02x?}; send-key[0..8]={:02x?}",
                                    &device_fp[..8],
                                    &rsession.send.key_for_test()[..8]
                                );
                                established = Some((rsession, device_fp));
                            }
                            None => eprintln!(" [sim] responder_write_msg2 failed"),
                        }
                    }
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
            let gen = arg_val("--gen").and_then(|s| s.parse().ok()).unwrap_or(1u64);
            if let Err(e) = run_live(&dev_ip, dev_id, gen) {
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
