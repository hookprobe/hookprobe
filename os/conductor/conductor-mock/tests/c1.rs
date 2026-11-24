// SPDX-License-Identifier: AGPL-3.0-only
//! C1: the signer's sealed state (delegation counter, revocation epoch) on a block device, with ADR 0069's
//! record scheme.
//! - drift gate: the record layout and rules equal the kernel's `g19ctr.rs` (read as text);
//! - power loss at every write, torn at every interesting length: no counter is ever handed out twice, and a
//!   confirmed epoch bump is never lost;
//! - the signer end to end on that disk: counters in signed capabilities strictly increase across crashes and
//!   reboots, and the kill switch survives a reboot.
use conductor_core::cap;
use conductor_core::class::Tier;
use conductor_core::crypto::{public_key, sha256};
use conductor_core::durable::{self, BlockDev, IoError, Sealed, MAGIC_DELEGATION, MAGIC_EPOCH, MAGIC_G19};
use conductor_core::signer::{CounterStore, SignRefusal, Signer};
use conductor_mock::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// ------------------------------------------------------------------ a disk that loses power

/// Sectors that survive power loss, shared between "boots".
#[derive(Default, Clone)]
struct Platter(Rc<RefCell<HashMap<u64, [u8; 512]>>>);

/// A view of the platter for one boot. After `writes_left` writes reach zero, the next write is torn (its first
/// `torn` bytes land, the rest of the sector keeps its old content) and the power goes: every later operation
/// fails. `bad_readback` makes the next read of a just-written sector return different bytes.
struct Disk {
    p: Platter,
    writes_left: Option<usize>,
    torn: usize,
    dead: bool,
    bad_readback: bool,
}

impl Disk {
    fn new(p: &Platter) -> Self {
        Disk { p: p.clone(), writes_left: None, torn: 0, dead: false, bad_readback: false }
    }
    fn crashing(p: &Platter, after: usize, torn: usize) -> Self {
        Disk { p: p.clone(), writes_left: Some(after), torn, dead: false, bad_readback: false }
    }
}

impl BlockDev for Disk {
    fn read_block(&self, lba: u64, out: &mut [u8; 512]) -> Result<(), IoError> {
        if self.dead {
            return Err(IoError);
        }
        *out = self.p.0.borrow().get(&lba).copied().unwrap_or([0; 512]);
        if self.bad_readback {
            out[100] ^= 1;
        }
        Ok(())
    }
    fn write_block(&mut self, lba: u64, data: &[u8; 512]) -> Result<(), IoError> {
        if self.dead {
            return Err(IoError);
        }
        if let Some(n) = self.writes_left.as_mut() {
            if *n == 0 {
                let mut m = self.p.0.borrow_mut();
                let old = m.get(&lba).copied().unwrap_or([0; 512]);
                let mut s = old;
                s[..self.torn].copy_from_slice(&data[..self.torn]);
                m.insert(lba, s);
                self.dead = true;
                return Err(IoError);
            }
            *n -= 1;
        }
        self.p.0.borrow_mut().insert(lba, *data);
        Ok(())
    }
}

const TORN: [usize; 9] = [0, 1, 8, 15, 16, 47, 48, 100, 512];

// ------------------------------------------------------------------ drift gate against the kernel

#[test]
fn record_scheme_equals_the_kernels_adr_0069_counter() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kernel/kernel/src/g19ctr.rs");
    let src = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    for f in [
        r#"const MAGIC: &[u8; 8] = b"HQG19C1\0";"#,
        "s[..8].copy_from_slice(MAGIC);",
        "s[8..16].copy_from_slice(&ctr.to_le_bytes());",
        "let h = boot_abi::sha256::digest(&s[..16]);",
        "s[16..48].copy_from_slice(&h);",
        "let slot = next % 2;",
        "d.write_block(lo + slot, &s).ok()?;",
        "(r == s).then_some(next)",
        "best = best.max(c);",
    ] {
        assert!(src.contains(f), "g19ctr.rs no longer contains `{f}`: update conductor_core::durable to match ADR 0069");
    }
    // Our encoder with the kernel's magic produces the kernel's record, byte for byte.
    let r = durable::encode(MAGIC_G19, 0x0102_0304_0506_0708);
    assert_eq!(&r[..8], b"HQG19C1\0");
    assert_eq!(&r[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&r[16..48], &sha256(&[&r[..16]]));
    assert!(r[48..].iter().all(|&b| b == 0));
    // Distinct magics: a sector written for one use never reads as another.
    assert_eq!(durable::decode(MAGIC_EPOCH, &durable::encode(MAGIC_DELEGATION, 5)), None);
    assert_eq!(durable::decode(MAGIC_DELEGATION, &durable::encode(MAGIC_DELEGATION, 5)), Some(5));
    println!("drift gate: the C1 sealed-store record equals the kernel's ADR 0069 g19ctr record");
}

// ------------------------------------------------------------------ power loss at every step

#[test]
fn power_loss_never_reuses_a_counter_and_never_loses_a_confirmed_epoch() {
    let (mut cases, mut handed_out_total) = (0usize, 0usize);
    for crash_at in 0..24usize {
        for torn in TORN {
            let p = Platter::default();
            // Boot 1: advance until the power goes; remember every value handed out.
            let mut d = Disk::crashing(&p, crash_at, torn);
            let mut handed = vec![];
            for _ in 0..30 {
                if let Some(v) = durable::advance(&mut d, MAGIC_DELEGATION, 2058) {
                    handed.push(v);
                } else {
                    break;
                }
            }
            assert!(handed.windows(2).all(|w| w[0] < w[1]));
            // Boot 2: the durable value is at least every value handed out, and the next one is new.
            let mut d2 = Disk::new(&p);
            let now = durable::load(&d2, MAGIC_DELEGATION, 2058).unwrap();
            assert!(handed.last().is_none_or(|&m| now >= m), "crash at {crash_at}, torn {torn}: durable {now} < handed {:?}", handed.last());
            let next = durable::advance(&mut d2, MAGIC_DELEGATION, 2058).unwrap();
            assert!(!handed.contains(&next), "counter {next} handed out twice");
            handed_out_total += handed.len();
            cases += 1;
        }
    }
    // A failed read-back hands out nothing.
    let p = Platter::default();
    let mut d = Disk::new(&p);
    d.bad_readback = true;
    assert_eq!(durable::advance(&mut d, MAGIC_DELEGATION, 2058), None);
    // Epoch: a bump that returned is durable; a torn bump is either the old or the new epoch, never lower.
    for crash_at in 0..12usize {
        for torn in TORN {
            let p = Platter::default();
            let mut s = Sealed { dev: Disk::crashing(&p, crash_at, torn), counter_lo: 2058, epoch_lo: 2060 };
            let mut confirmed = 1u32;
            for _ in 0..8 {
                match s.bump_epoch() {
                    Some(e) => {
                        assert!(e > confirmed);
                        confirmed = e;
                    }
                    None => break,
                }
            }
            let s2 = Sealed { dev: Disk::new(&p), counter_lo: 2058, epoch_lo: 2060 };
            let e = s2.epoch().unwrap();
            assert!(e >= confirmed, "crash at {crash_at}, torn {torn}: epoch {e} < confirmed {confirmed}");
            cases += 1;
        }
    }
    println!("power loss: {cases} crash points (every write, 9 torn lengths): no counter handed out twice ({handed_out_total} handed out), no confirmed epoch lost");
}

// ------------------------------------------------------------------ the signer on the disk

fn request_bytes() -> Vec<u8> {
    let mut b = vec![0u8; 128];
    let n = conductor_core::frame::Request { op: cap::op::INFER, model_digest: MODEL, prompt: b"hi" }.encode(&mut b).unwrap();
    b.truncate(n);
    b
}

fn request() -> cap::SignRequest {
    cap::SignRequest {
        tier: 1,
        worker_public_key: public_key(&WORKER_SEED),
        session_binding: [5; 32],
        job_id: [1; 16],
        request_hash: sha256(&[&request_bytes()]),
        model_digest: MODEL,
        operations: cap::op::INFER,
        data_classes: 1,
        egress_policy_id: EGRESS,
        max_input_units: 10,
        max_output_units: 10,
        max_compute_ms: 100,
        max_response_bytes: 100,
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

fn signer(dev: Disk) -> Signer<Sealed<Disk>> {
    let mut s = Signer::new(DEVICE_SEED, SALT_KEY, public_key(&OWNER_SEED), policy_p1(), Sealed { dev, counter_lo: 2058, epoch_lo: 2060 });
    let (rec, sig) = owner_pairing(Tier::P1, public_key(&WORKER_SEED), u64::MAX, 1);
    s.install_pairing(&rec, &sig).unwrap();
    s
}

#[test]
fn signer_on_a_sealed_disk_survives_crashes_and_reboots() {
    let p = Platter::default();
    let mut e = |b: &mut [u8]| b.fill(3);
    let mut seen = vec![];
    let mut boots = 0;
    // Ten boots, each losing power after a different number of writes, torn differently.
    for boot in 0..10usize {
        let mut s = signer(Disk::crashing(&p, 3 + boot % 4, TORN[boot % TORN.len()]));
        boots += 1;
        loop {
            match s.sign(&request(), 1_000, &mut e) {
                Ok(signed) => {
                    let c = cap::open(&signed, &s.public_key()).unwrap();
                    assert!(seen.last().is_none_or(|&l| c.counter > l), "counter {} after {:?}", c.counter, seen.last());
                    seen.push(c.counter);
                }
                Err(SignRefusal::Counter | SignRefusal::Epoch) => break, // power gone: nothing signed
                Err(other) => panic!("unexpected refusal {other:?}"),
            }
        }
    }
    assert!(seen.len() >= 20, "too few signatures: {}", seen.len());
    // The kill switch on the disk: confirmed, rebooted, still in force; old capabilities refused by a worker.
    let mut s = signer(Disk::new(&p));
    let old = s.sign(&request(), 1_000, &mut e).unwrap();
    let before = s.epoch().unwrap();
    let after = s.bump_epoch().unwrap();
    assert_eq!(after, before + 1);
    let s2 = signer(Disk::new(&p));
    assert_eq!(s2.epoch(), Some(after), "the epoch must survive a reboot");
    let ann = s2.announce_epoch(2_000).unwrap();
    let mut gate = MockWorker::new(Tier::P1, vec![]).gate;
    assert_eq!(gate.apply_epoch(&ann), Ok(after));
    assert_eq!(gate.accept(&old, &[5; 32], &request_bytes(), Some(3_000)).unwrap_err(), conductor_core::worker::Refuse::Revoked, "a capability from before the kill switch must be refused as revoked");
    // An unreadable store signs nothing and announces nothing.
    let mut dead = Disk::new(&p);
    dead.dead = true;
    let mut s3 = signer(dead);
    assert_eq!(s3.sign(&request(), 1_000, &mut e).err(), Some(SignRefusal::Epoch));
    assert!(s3.announce_epoch(1).is_none());
    assert!(s3.bump_epoch().is_none());
    println!("signer on a sealed disk: {} signatures over {boots} crashing boots, counters strictly increasing; epoch {after} survives a reboot and revokes", seen.len());
}

