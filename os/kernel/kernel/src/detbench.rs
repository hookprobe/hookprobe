//! Detection-accuracy benchmark (readiness checklist 4.1): replay a LABELLED frame corpus through the real
//! detection pipeline (`packet::verdict` → the signed rule plane, rate / scan / behavioural tiers, JA4, IOC)
//! with the detectors' clock pinned to each frame's recorded time, and count every alert per rule and per
//! label. Benign-labelled alerts are false positives; per-attack-label alerts give the detection coverage.
//!
//! QEMU only (`--features detbench`): the corpus is a raw virtio disk built on the host by
//! `tools/detbench/pcap2hqdb.py` from pcaps + label rules. Format `HQDB1`:
//!   LBA 0: "HQDB1\0\0\0" | nrec u64 | nlabels u8 | … | label names at byte 64 (16 bytes each, ≤ 15)
//!   LBA 1…: a byte stream of records  ts_us u64 | label u8 | 0 | len u16 | frame[len]
//! Output: `[DETBENCH] …` lines on the console, parsed by `tools/detbench/run.sh` into a report.

use arch_aarch64::virtio_blk::VirtioBlk;
use hal::BlockDev;

const MAX_LABELS: usize = 15;
const MAX_RULES: usize = 64;

struct Reader<'a> {
    dev: &'a VirtioBlk,
    lba: u64,
    sec: [u8; 512],
    off: usize,
    end: u64,
}
impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        if self.off == 512 {
            if self.lba >= self.end {
                return None;
            }
            self.dev.read_block(self.lba, &mut self.sec).ok()?;
            self.lba += 1;
            self.off = 0;
        }
        let b = self.sec[self.off];
        self.off += 1;
        Some(b)
    }
    fn fill(&mut self, out: &mut [u8]) -> Option<()> {
        for b in out.iter_mut() {
            *b = self.byte()?;
        }
        Some(())
    }
}

/// Run the benchmark if a corpus disk is attached. Returns false when there is none.
pub fn run() -> bool {
    let Some(dev) = VirtioBlk::open() else { return false };
    let mut h = [0u8; 512];
    if dev.read_block(0, &mut h).is_err() || &h[..8] != b"HQDB1\0\0\0" {
        return false;
    }
    let nrec = u64::from_le_bytes(h[8..16].try_into().unwrap());
    let nlab = (h[16] as usize).min(MAX_LABELS);
    let label = |i: usize| -> &str {
        let n = &h[64 + i * 16..64 + i * 16 + 16];
        core::str::from_utf8(&n[..n.iter().position(|&c| c == 0).unwrap_or(16)]).unwrap_or("?")
    };
    let mut frames = [0u64; MAX_LABELS];
    let mut drops = [0u64; MAX_LABELS];
    // (rule id, alerts per label)
    let mut rules: [(u16, [u64; MAX_LABELS]); MAX_RULES] = [(0, [0; MAX_LABELS]); MAX_RULES];
    let mut nrules = 0usize;
    let freq = crate::clock::freq().max(1);
    let mut rd = Reader { dev: &dev, lba: 1, sec: [0; 512], off: 512, end: dev.block_count() };
    let mut f = [0u8; 2048];
    let mut evs = [crate::events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0, class: 0, dport: 0, dst: 0 }; 32];
    let mut done = 0u64;
    let mut t0 = 0u64;
    crate::rules::refire_reset();
    crate::behavioral::brute_reset();
    crate::behavioral::beacon_reset_for_test();
    crate::rules::arp_binding_reset();
    for _ in 0..nrec {
        let mut hd = [0u8; 12];
        if rd.fill(&mut hd).is_none() {
            break;
        }
        let ts_us = u64::from_le_bytes(hd[0..8].try_into().unwrap());
        let lab = (hd[8] as usize).min(MAX_LABELS - 1);
        let len = u16::from_le_bytes([hd[10], hd[11]]) as usize;
        if len > f.len() || rd.fill(&mut f[..len]).is_none() {
            break;
        }
        if t0 == 0 {
            t0 = ts_us;
        }
        // replay clock: the corpus starts 1 s after boot-time zero, real spacing preserved
        let rel = ts_us.saturating_sub(t0) + 1_000_000;
        crate::clock::replay_set((rel as u128 * freq as u128 / 1_000_000) as u64);
        frames[lab] += 1;
        if crate::packet::verdict(&f[..len]).1 == crate::packet::DROP {
            drops[lab] += 1;
        }
        // the AP's forwarding path: outbound bytes per inside source (exfil, parity G3), LAN -> internet only
        if len >= 34 && f[12] == 0x08 && f[13] == 0x00 && f[26..29] == [10, 99, 0] && f[30..33] != [10, 99, 0] {
            let src = u32::from_be_bytes([f[26], f[27], f[28], f[29]]);
            let dst = u32::from_be_bytes([f[30], f[31], f[32], f[33]]);
            let _ = crate::rules::exfil_verdict(src, dst, u16::from_be_bytes([f[16], f[17]]) as u64);
        }
        // the AP's DNS path too (Shield decisions, DGA scoring, IOC domains) — it reports through the same events
        let mut dr = [0u8; 600];
        let _ = crate::shield::on_client_frame(&f[..len], &[0x02, 0, 0, 0, 0, 0x01], &mut dr, crate::clock::ticks());
        let n = crate::events::drain(&mut evs);
        for e in &evs[..n] {
            let i = match rules[..nrules].iter().position(|r| r.0 == e.rule_id) {
                Some(i) => i,
                None if nrules < MAX_RULES => {
                    rules[nrules].0 = e.rule_id;
                    nrules += 1;
                    nrules - 1
                }
                None => continue,
            };
            rules[i].1[lab] += 1;
        }
        done += 1;
    }
    crate::clock::replay_set(0);
    arch_aarch64::_print(format_args!(" [DETBENCH] corpus: {} of {} records replayed, {} labels\n", done, nrec, nlab));
    for l in 0..nlab {
        arch_aarch64::_print(format_args!(" [DETBENCH] label={} frames={} drops={}\n", label(l), frames[l], drops[l]));
    }
    rules[..nrules].sort_unstable_by_key(|r| r.0);
    for r in &rules[..nrules] {
        let info = crate::rulecat::lookup_or_generic(r.0);
        arch_aarch64::_print(format_args!(" [DETBENCH] rule={} msg=\"{}\"", r.0, info.msg));
        for l in 0..nlab {
            arch_aarch64::_print(format_args!(" {}={}", label(l), r.1[l]));
        }
        arch_aarch64::_print(format_args!("\n"));
    }
    arch_aarch64::_print(format_args!(" [DETBENCH] DONE\n"));
    true
}
