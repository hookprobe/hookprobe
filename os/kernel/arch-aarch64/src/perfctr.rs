//! ADR 0067 D1 — work counters. A work counter is a count of work done on a fixed input (table
//! entries examined, bytes checksummed, round trips), so it is the same number on every run and
//! under QEMU. Self-tests emit one line per counter; `tools/ci/perf_ratchet.py` compares the
//! lines with `tools/ci/baselines/perf.json` in gate g2. Timings are not work counters: QEMU
//! timing is never evidence, and metal timings are gated separately (g6).
use core::sync::atomic::{AtomicU32, Ordering};

static EMITTED: AtomicU32 = AtomicU32::new(0);

/// Emit one work counter as ` [PERF] name=value`.
pub fn emit(name: &str, value: u64) {
    crate::_print(format_args!(" [PERF] {}={}\n", name, value));
    EMITTED.fetch_add(1, Ordering::Relaxed);
}

/// `[P-perfctr]` — the boot self-tests emitted their work counters.
pub fn report() -> bool {
    let n = EMITTED.load(Ordering::Relaxed);
    let pass = n > 0;
    crate::_print(format_args!(
        " [P-perfctr] {} — {} work counters emitted as [PERF] lines (ADR 0067 D1; compared with tools/ci/baselines/perf.json by the g2 performance ratchet)\n",
        if pass { "PASS" } else { "FAIL" }, n));
    pass
}
