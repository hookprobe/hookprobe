// SPDX-License-Identifier: AGPL-3.0-only
//! QEMU integration-test profile (`qemu-itest`, operator decision 2026-11-22, G19 S1): the self-tests of the
//! virtio-rng entropy leaf. Never in a CM5 / cloud image (compile-time refused in entropy.rs).
//!
//! `[P-itest-rng]` — with `-device virtio-rng-device`: the production `MetalEntropy<HwTrng>` passes its startup health
//! check over virtio-rng, a 4 KiB fill has a sane bit balance, two fills differ, the driver counted real device round
//! trips, and the health check rejects a stuck source (a local test double, never a key source).
//! Without the device the same boot prints `[P-itest-rng] FAIL-CLOSED` — no entropy, so no keys, no handshake — and the
//! runner (tools/itest-qemu.sh) asserts that line for the negative run.
#![cfg(feature = "qemu-itest")]

use crate::entropy::{boot_health_assert, EntropySource, HwTrng, MetalEntropy, RawTrng};

macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }

/// A stuck raw source — test double for the health-check refusal ONLY (never handed to a key generator).
struct Stuck;
impl RawTrng for Stuck {
    fn next_word(&mut self) -> Option<u64> {
        Some(0x5a5a_5a5a_5a5a_5a5a)
    }
}

pub fn selftest() -> bool {
    let health = boot_health_assert();
    let (present, _, _, why) = arch_aarch64::virtio_rng::status();
    if health.is_err() {
        kprint!(" [P-itest-rng] FAIL-CLOSED — {:?}: virtio-rng {} ({}) -> no entropy, so no key generation and no G19 handshake (no timer/counter fallback exists)\n",
            health, if present { "present but failing" } else { "absent" }, arch_aarch64::virtio_rng::dead_reason(why));
        return false;
    }
    let mut src = MetalEntropy::new(HwTrng::new());
    let (mut a, mut b) = ([0u8; 4096], [0u8; 4096]);
    let fa = src.fill(&mut a).is_ok();
    let fb = src.fill(&mut b).is_ok();
    let ones: u32 = a.iter().map(|x| x.count_ones()).sum();
    // 32,768 bits: mean 16,384, sigma ~90.5 — a ±6-sigma window (a broken / constant source lands far outside)
    let balanced = (16_384 - 543..=16_384 + 543).contains(&ones);
    let differ = a != b && a.iter().any(|x| *x != 0);
    let (_, words, requests, why2) = arch_aarch64::virtio_rng::status();
    let counted = words >= 1024 && requests >= 128 && why2 == 0;
    let stuck_refused = MetalEntropy::new(Stuck).health_check().is_err();
    let pass = fa && fb && balanced && differ && counted && stuck_refused;
    kprint!(" [P-itest-rng] {} — QEMU integration-test profile: MetalEntropy<HwTrng> over virtio-rng health-checked=true; 2 x 4 KiB fills={} bit balance {} of 32768 in the 6-sigma window={}; fills differ and are not zero={}; device round trips {} / words {} (no fallback path)={}; a stuck source is refused by the same health check={}\n",
        if pass { "PASS" } else { "FAIL" }, fa && fb, ones, balanced, differ, requests, words, counted, stuck_refused);
    // the buffers held key-grade bytes: wipe them
    a.fill(0);
    b.fill(0);
    pass
}
