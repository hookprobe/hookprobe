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
//!   responder-sim --live --dev-pk HEX [--dev-ip IP] [--evidence-out PATH]
//!                                        bind UDP :7654, reassemble the device's broadcast
//!                                        msg1, answer msg2 unicast; print Established + keys;
//!                                        serve the reach policy; receive M6 evidence exports
//!                                        (HQXR-tagged datagram records) → evidence JSONL.
//!
//! The responder STATIC keypair is derived from the SAME provisioning seeds whose PUBLIC half
//! is baked into the device image (kernel testdata/provisioned_mssp_pub.bin), so the device
//! authenticates this responder. The device's ed25519 identity is SRK-derived on-device and
//! never re-derivable here: pass the public key the device prints at boot
//! (`[NETCP] device identity (SRK-derived) pk=…`) as --dev-pk — that IS the enrollment step.

mod entropy;

// The kernel secure-channel module, verbatim. `crate::entropy` inside it resolves to the
// shim above; `boot_abi` + the RustCrypto crates resolve to this crate's deps.
#[path = "../../heqk/kernel/src/securechannel.rs"]
mod securechannel;
// The kernel M6 export wire codec, verbatim (pure, no crate deps).
#[path = "../../heqk/kernel/src/exportwire.rs"]
#[allow(dead_code)]
mod exportwire;
mod export_rx;

use boot_abi::sha256;
use ed25519_compact::{KeyPair, PublicKey as EdPub, Seed};
use entropy::OsEntropy;
use securechannel::{
    hs_chunk, initiator_read_msg2, initiator_write_msg1, responder_read_msg1, responder_write_msg2, HsReasm,
    InitiatorRandomness, ResponderPub, ResponderRandomness, ResponderStatic,
};
use std::net::UdpSocket;

const HS_PORT: u16 = 7654;

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

/// Parse the device's published Ed25519 identity public key (64 hex chars).
fn parse_dev_pk(hexs: &str) -> Option<EdPub> {
    let h = hexs.trim();
    if h.len() != 64 {
        return None;
    }
    let mut b = [0u8; 32];
    for (i, out) in b.iter_mut().enumerate() {
        *out = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    EdPub::from_slice(&b).ok()
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
    // A throwaway device identity for the in-process check (the real one is SRK-derived on-device).
    let dev_kp = KeyPair::from_seed(Seed::new(sha256::digest(b"responder-sim-selftest-device")));
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
    let (msg2, rsession) = match responder_write_msg2(rpend, &rrand, &SEG_TENANT.to_le_bytes()) {
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

/// One Established device session: the Noise session (reach policy, stream records) plus the
/// M6 export receiver over the SAME session's recv key (datagram records, own AD + window).
struct Live {
    session: securechannel::Session,
    device_fp: [u8; 32],
    exports: export_rx::ExportRx,
    policy_served: bool,
}

fn epoch_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Live responder: bind UDP :7654, reassemble the device's broadcast msg1, answer msg2
/// unicast to `dev_ip`, serve the reach policy, and receive M6 evidence exports into
/// `evidence_out` (JSON Lines for hookprobe-evidence). Loops so repeated device attempts are
/// all served.
fn run_live(dev_ip: &str, dev_pk: EdPub, gen: u64, evidence_out: &str) -> std::io::Result<()> {
    use std::io::Write;
    let resp = responder_static();
    print_pub_hex(" [sim] responder MSSP pub:", &resp.public());
    let dpk_bytes: &[u8] = dev_pk.as_ref();
    println!(" [sim] enrolled device pk (first 8 bytes) {:02x?}; tenant={SEG_TENANT:#x} (sent in msg2)", &dpk_bytes[..8]);

    let op_kp = operator_keypair();
    let op_pk: &[u8] = op_kp.pk.as_ref();
    println!(" [sim] operator signing pubkey (bake into device as OPERATOR_PK): {}",
        op_pk.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let mut evidence = std::fs::OpenOptions::new().create(true).append(true).open(evidence_out)?;
    let sock = UdpSocket::bind(("0.0.0.0", HS_PORT))?;
    sock.set_broadcast(true)?;
    println!(" [sim] listening on 0.0.0.0:{HS_PORT} (broadcast); policy → {dev_ip}:{HS_PORT}; evidence → {evidence_out}");

    let mut reasm = HsReasm::new();
    let mut buf = [0u8; 2048];
    let mut live: Option<Live> = None;
    let mut handshakes = 0u32;
    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        // Skip the 90 B presence beacon (UDP payload starts "HEQK-ENROLL-HELO").
        if buf[..n].starts_with(b"HEQK-ENROLL") {
            continue;
        }

        // M6 EXPORT — tagged datagram records (demuxed on the tag, never trial-decrypted).
        if buf[..n].starts_with(&exportwire::DGRAM_TAG[..]) {
            match live.as_mut() {
                Some(l) => match l.exports.accept(&buf[..n]) {
                    Ok(f) => {
                        let lines = export_rx::frame_to_jsonl(&f, &l.exports.tracker, epoch_now());
                        for line in &lines {
                            writeln!(evidence, "{line}")?;
                        }
                        evidence.flush()?;
                        println!(" [sim] M6 export frame #{} boots={} events={} qsecbit={} | gap={} late={} device_lost={} overruns={}",
                            f.hdr.frame_seq, f.hdr.boots, f.n, f.hdr.qsecbit_score, l.exports.tracker.gap_events,
                            l.exports.tracker.late_events, f.hdr.lost, f.hdr.overruns);
                    }
                    Err(e) => eprintln!(" [sim] M6 export refused: {e:?}"),
                },
                None => eprintln!(" [sim] M6 export before any session — dropped"),
            }
            continue;
        }

        // POLICY phase — Established: decrypt the REQ over the Session, serve the signed policy.
        if let Some(l) = live.as_mut() {
            let mut reqpt = [0u8; 64];
            let decoded = if l.policy_served {
                None
            } else {
                l.session.recv.decrypt_into(b"", &buf[..n], &mut reqpt).ok().map(|got| &reqpt[..got] == REACH_POLICY_REQ)
            };
            match decoded {
                Some(true) => {
                    let pol = build_signed_policy(gen, SEG_TENANT, &l.device_fp);
                    let mut rec = [0u8; RP_WIRE_LEN + 16];
                    match l.session.send.encrypt_into(b"", &pol, &mut rec) {
                        Some(rl) => {
                            let ok = sock.send_to(&rec[..rl], (dev_ip, HS_PORT)).is_ok();
                            println!(" [sim] ✅ REQ received; operator-signed ReachPolicy sent (gen={gen} tenant=TENA, MAC 02..10=Quarantine, 0a..11=InternetOnly; {RP_WIRE_LEN} B plaintext → {rl} B record, sent_ok={ok}) — device should verify+ARM");
                        }
                        None => eprintln!(" [sim] policy encrypt failed"),
                    }
                    // One policy per session; the session STAYS up for M6 exports.
                    l.policy_served = true;
                    continue;
                }
                Some(false) => continue, // decrypted on this Session but not the REQ opcode
                None => {
                    // Not a tagged export and not decryptable as the REQ → a NEW handshake
                    // attempt (e.g. the device rebooted). Drop the stale session + fall through.
                    println!(" [sim] new handshake attempt detected — resetting the session");
                    live = None;
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
                        // device_fp binds the reach policy AND every exported evidence record. Review Q2-H1:
                        // it used to be taken from the device's own msg1 claim. It is now DERIVED from the
                        // key this handshake just authenticated (sha256(dev_pk)); a device claiming any other
                        // fingerprint is refused — it could otherwise file evidence as another device.
                        let device_fp = sha256::digest(dev_pk.as_ref());
                        if rpend.payload1.as_slice() != &device_fp[..] {
                            eprintln!(" [sim] REFUSED: msg1 claims device_fp {:02x?}.. but the authenticated key's is {:02x?}.. (Q2-H1)",
                                &rpend.payload1.as_slice()[..rpend.payload1.as_slice().len().min(8)], &device_fp[..8]);
                            reasm = HsReasm::new();
                            continue;
                        }
                        match responder_write_msg2(rpend, &rrand, &SEG_TENANT.to_le_bytes()) {
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
                                let exports = export_rx::ExportRx::new(rsession.recv.into_anti_replay(), SEG_TENANT, device_fp);
                                live = Some(Live { session: rsession, device_fp, exports, policy_served: false });
                            }
                            None => eprintln!(" [sim] responder_write_msg2 failed"),
                        }
                    }
                    Err(e) => eprintln!(" [sim] responder_read_msg1 rejected the device: {e:?} \
                        (pk mismatch? pass the pk the device prints at boot as --dev-pk)"),
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
    let usage = "usage: responder-sim [--selftest | --live --dev-pk HEX [--dev-ip IP] [--gen N] [--evidence-out PATH]]";
    match mode {
        "--selftest" => {
            std::process::exit(if selftest() { 0 } else { 1 });
        }
        "--live" => {
            let dev_ip = arg_val("--dev-ip").unwrap_or_else(|| "10.200.0.2".to_string());
            let dev_pk = match arg_val("--dev-pk").as_deref().and_then(parse_dev_pk) {
                Some(pk) => pk,
                None => {
                    eprintln!("{usage}\n  --dev-pk is required: the 64-hex public key the device prints at boot");
                    eprintln!("  ([NETCP] device identity (SRK-derived) pk=…). It is no longer derivable from the serial.");
                    std::process::exit(2);
                }
            };
            let gen = arg_val("--gen").and_then(|s| s.parse().ok()).unwrap_or(1u64);
            let out = arg_val("--evidence-out").unwrap_or_else(|| "heqk-evidence.jsonl".to_string());
            if let Err(e) = run_live(&dev_ip, dev_pk, gen, &out) {
                eprintln!(" [sim] fatal: {e}");
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("{usage}");
            eprintln!("  unknown mode: {other}");
            std::process::exit(2);
        }
    }
}
