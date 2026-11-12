#![no_main]
// A9 (audit 2026-11-10 §4): the owner journal REPLAY on attacker-shaped eMMC contents. Every boot rebuilds the owner
// rules (device policy, Shield allow/block, labels, alert hook, owner-key rotation, factory-reset request, artifact
// audits) from this region, and a person with the card in a reader can write anything there.
//   mode 0 — raw sectors: the MAC gate must refuse cleanly (no panic, no rule applied without a valid chain).
//   mode 1 — a VALID MAC chain (the harness holds the unit key, as the kernel does) over fuzzed record bodies, so
//            `apply` and every record decoder behind the MAC gate see arbitrary kinds / ops / lengths.
// After each replay: the accessors must not panic, the rule table stays bounded, a second replay of the same bytes
// gives the same result (replay is a pure function of the disk), and an append on top either succeeds and survives
// the next replay or is refused — never a panic.
use hal::{BlockDev, BlockErr};
use heqk_kernel_fuzz::ownerjournal as oj;
use libfuzzer_sys::fuzz_target;

const SECT: usize = 16; // two halves of 8 sectors = 16 records each
const SRK: [u8; 32] = [0x42; 32];

struct Disk {
    s: [[u8; 512]; SECT],
}
impl BlockDev for Disk {
    fn block_count(&self) -> u64 {
        SECT as u64
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        let s = self.s.get(lba as usize).ok_or(BlockErr::OutOfRange)?;
        buf.copy_from_slice(s);
        Ok(())
    }
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        let s = self.s.get_mut(lba as usize).ok_or(BlockErr::OutOfRange)?;
        s.copy_from_slice(buf);
        Ok(())
    }
}

fn key() -> [u8; 32] {
    let prk = boot_abi::kdf::hkdf_extract(b"HQ-owner-journal", &SRK);
    boot_abi::kdf::hkdf_expand32(&prk, b"HQ-owner-journal-v1")
}

/// Seal one 256-byte record in place (body bytes 0..224 are MAC'd, the MAC goes in 224..256), chained on `prev`.
fn seal(k: &[u8; 32], prev: &[u8; 32], r: &mut [u8]) -> [u8; 32] {
    let m = boot_abi::kdf::hmac_sha256_2(k, prev, &r[..224]);
    r[224..256].copy_from_slice(&m);
    m
}

fn put(d: &mut Disk, half: usize, idx: usize, rec: &[u8; 256]) {
    let lba = half * (SECT / 2) + idx / 2;
    let off = (idx % 2) * 256;
    d.s[lba][off..off + 256].copy_from_slice(rec);
}

/// Everything observable after a replay, for the determinism check.
fn snapshot(r: &oj::Replay) -> (u32, bool, bool, bool, usize, bool, bool) {
    let mut n = 0usize;
    oj::for_each(&mut |x| {
        assert!(x.tlen as usize <= oj::TARGET_MAX);
        n += 1;
    });
    assert_eq!(n, oj::rule_count());
    assert!(n <= oj::MAX_RULES);
    let mut a = 0usize;
    oj::for_each_artifact(&mut |_| a += 1);
    assert!(a <= oj::ART_N);
    let mut l = 0usize;
    oj::for_each_label(&mut |x| {
        assert!(oj::label_ok(&x.label[..x.len as usize]));
        l += 1;
    });
    assert!(l <= oj::LABELS_N);
    let mac = [0x02, 0, 0, 0, 0, 0x71];
    let _ = (oj::device_policy(&mac), oj::shield_profile(&mac), oj::shield_allowed(b"a.example"), oj::shield_blocked(b"a.example"));
    let mut lb = [0u8; oj::LABEL_MAX];
    assert!(oj::owner_label(&mac, &mut lb) <= oj::LABEL_MAX);
    (r.records, r.damaged, r.full, r.rollback, n, oj::owner_rotation().is_some(), oj::factory_reset_requested())
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mut d = Disk { s: [[0u8; 512]; SECT] };
    let body = &data[1..];
    if data[0] & 1 == 0 {
        // raw sectors, as written by someone with the card in a reader
        for (i, c) in body.chunks(512).take(SECT).enumerate() {
            d.s[i][..c.len()].copy_from_slice(c);
        }
    } else {
        // a valid chain: header (epoch, base seq) + fuzzed records with correct seq / epoch / MAC
        let k = key();
        let half = (data[0] >> 1 & 1) as usize;
        let epoch = 1 + (data[0] >> 2) as u32;
        let base = 1u64;
        let mut h = [0u8; 256];
        h[0..4].copy_from_slice(b"HQOJ");
        h[24] = 0xEE;
        h[27] = 12;
        h[28..32].copy_from_slice(&epoch.to_le_bytes());
        h[32..40].copy_from_slice(&base.to_le_bytes());
        h[192..196].copy_from_slice(&epoch.to_le_bytes());
        let mut prev = seal(&k, &[0u8; 32], &mut h);
        put(&mut d, half, 0, &h);
        // each fuzzed record supplies bytes 12..192 (time, session, kind, op, flags, lengths, target, value, reason)
        for (i, c) in body.chunks(180).take(SECT - 1).enumerate() {
            let mut r = [0u8; 256];
            r[0..4].copy_from_slice(b"HQOJ");
            r[4..12].copy_from_slice(&(base + i as u64).to_le_bytes());
            r[12..12 + c.len()].copy_from_slice(c);
            r[192..196].copy_from_slice(&epoch.to_le_bytes());
            prev = seal(&k, &prev, &mut r);
            put(&mut d, half, i + 1, &r);
        }
    }
    let mut j = oj::Journal::new(0, SECT as u64, &SRK);
    let r1 = j.replay(&d);
    let s1 = snapshot(&r1);
    if data[0] & 1 == 0 {
        // without the unit key nothing can be applied
        assert_eq!(s1.4, 0, "a rule was applied from unsealed bytes");
        assert_eq!(r1.records, 0);
    }
    let mut j2 = oj::Journal::new(0, SECT as u64, &SRK);
    let r2 = j2.replay(&d);
    assert_eq!(snapshot(&r2), s1, "replay is not a pure function of the disk");
    // an owner change on top: refused or persisted — and the next replay agrees with what was appended
    let before = oj::rule_count();
    let rec = oj::rec(oj::Kind::ShieldBlock, oj::OP_SET, b"fuzz.example", 1, b"fuzz");
    let res = j2.append(&mut d, rec);
    let mut j3 = oj::Journal::new(0, SECT as u64, &SRK);
    let r3 = j3.replay(&d);
    let _ = snapshot(&r3);
    if res.is_ok() {
        assert!(oj::shield_blocked(b"fuzz.example"), "an accepted append did not survive the replay");
        // (a damaged tail after the append point may still be reported — leftovers past it are not trusted)
    }
    let _ = before;
});
