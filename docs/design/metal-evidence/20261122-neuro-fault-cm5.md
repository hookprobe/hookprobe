# Neuro on CM5: el0-neuro fault injection (2026-11-22)

**Image:** `am36G-c3509d7a`, bench AP + `wpa3,neuro,wifi-inject`. `wifi-bigtx` was left out so the boot set fits the
5,242,880 B window.
**Tool:** `tools/diagnostics/cm5-neuro-fault-check.sh`.
**Trigger:** `POST /api/bench/wifi-inject kind=neuro-fault`, owner re-auth. It is a **counted** fault through the
real supervised call, not a self-test's deliberate one.
**Load:** the bench Pi browses through the AP throughout.

```
ok  am36G committed
ok  el0-neuro faulted: contained + reset          [NEURO] bench fault: reply Failed, server restarts 0 -> 1, memory lost (relearns) = true
ok  the AP still forwards right after the fault (Pi -> example.com: 200)
    burst of 10: faulted=7 held-off=3
ok  the supervisor held el0-neuro off during the burst (restart backoff)
    [NEURO beat] fed=623 dropped=35 batches=31 resets=8 | dp frames=30240 named=157 names=405
ok  Neuro keeps receiving events after the faults (fed 209 -> 623, relearning from cold)
ok  the AP loop never stalled (worst loop gap since boot 488 ms)
ok  no panic / crash
ok  bench restored to am35B
NEURO-FAULT-METAL: PASS (8/8)
```

**What it shows:**
- A Neuro fault ends in EL0. The kernel resets the server from its signed ELF, journals it, and applies the restart
  backoff, which refused 3 of 10 back-to-back calls.
- The AP never waits: Wi-Fi forwarding continued, and the worst loop gap was 488 ms against the 2 s gate.
- The events dropped while the server was held off are counted (`dropped=35`), and Neuro resumes afterwards.

**Defect found and fixed on this run.** The kernel delivered its event batch only when it was full (512) or at the
hour close, so events could wait up to an hour, and a fault discarded them. On the first run `fed` stayed 0 for
minutes. The host now flushes on every AP heartbeat tick (at most one excursion per 5 s). On the second run `fed` rose
from 209 to 623 across the faults.

**First run notes.** It scored 6/8 for two reasons, both fixed: the liveness probe used example.org, which is on the
bench Shield blocklist on purpose (it now uses example.com), and the batch flush above.
