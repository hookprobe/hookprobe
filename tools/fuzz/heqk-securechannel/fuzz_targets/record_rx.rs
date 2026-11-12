#![no_main]
// W4: the rekeying record receiver on an attacker-driven mix of genuine and forged datagrams. Ops (1 byte each,
// then arguments): 0 = seal a genuine record (len byte) and keep it; 1 = deliver kept record #i, optionally with
// one byte flipped; 2 = deliver raw attacker bytes; 3 = sender rekeys silently; 4 = time passes; 5 = arm.
// Invariants: never panics; the receiver's epoch never goes backwards; an attacker byte string or a modified
// record is never accepted unless it equals a genuine sealed record; a genuine record is accepted at most once;
// an accepted record decrypts to exactly what was sealed.
use heqk_securechannel_fuzz::securechannel::{RecordTx, RekeyPolicy};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static S: OnceLock<(heqk_securechannel_fuzz::securechannel::CipherState, heqk_securechannel_fuzz::securechannel::CipherState)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let (send, recv) = S.get_or_init(|| {
        let (i, r) = heqk_securechannel_fuzz::sessions();
        (i.send.clone(), r.recv.clone())
    });
    let pol = RekeyPolicy { max_records: 3, max_bytes: 200, max_ms: 1_000 };
    let mut tx = RecordTx::new(send.clone(), 0, pol);
    let mut rx = recv.into_record_rx();
    let ad = b"fuzz-ad";
    let mut kept: Vec<(Vec<u8>, Vec<u8>, bool)> = Vec::new(); // (record, plaintext, delivered)
    let (mut now, mut last_epoch) = (0i64, 0u32);
    let mut it = data.iter().copied();
    let mut out = [0u8; 300];
    while let Some(op) = it.next() {
        match op % 6 {
            0 => {
                let n = it.next().unwrap_or(0) as usize % 200;
                let pt: Vec<u8> = (0..n).map(|i| i as u8 ^ op).collect();
                let mut b = [0u8; 256];
                if let Some(l) = tx.seal(ad, &pt, &mut b, now) {
                    kept.push((b[..l].to_vec(), pt, false));
                }
            }
            1 if !kept.is_empty() => {
                let i = it.next().unwrap_or(0) as usize % kept.len();
                let flip = it.next().unwrap_or(0) as usize;
                let mut rec = kept[i].0.clone();
                let modified = flip % 4 != 0;
                if modified {
                    let at = flip % rec.len();
                    rec[at] ^= 1 << (flip % 8);
                }
                let r = rx.open(ad, &rec, &mut out, now);
                if let Ok(n) = r {
                    assert!(!modified, "a modified record was accepted");
                    assert!(!kept[i].2, "a genuine record was accepted twice");
                    assert_eq!(&out[..n], &kept[i].1[..], "wrong plaintext");
                    kept[i].2 = true;
                }
            }
            2 => {
                let n = it.next().unwrap_or(0) as usize % 64;
                let raw: Vec<u8> = it.by_ref().take(n).collect();
                if rx.open(ad, &raw, &mut out, now).is_ok() {
                    assert!(kept.iter().any(|k| k.0 == raw), "attacker bytes accepted");
                }
            }
            3 => {
                tx.rekey(now);
            }
            4 => now += it.next().unwrap_or(0) as i64 * 50,
            5 => tx.arm(),
            _ => {}
        }
        assert!(rx.epoch() >= last_epoch, "receiver epoch went backwards");
        last_epoch = rx.epoch();
    }
});
