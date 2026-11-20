# 20 — Temporal engine as evidence: the integration contract (P5)

> 2026-11-20. Operator decision: **wire the temporal tier as evidence.** This follows three pre-registered
> attempts to make it an alarm source, D1 (`17`), D1b (`18`) and D1c (`19`); all were rejected on real
> traffic.
>
> This document is what HomePods (kernel) and the UI need for P5 (`14`). It changes no kernel file.

## 1. Why evidence and not alerts

**What the engine does well.** On six months of real IoT traffic (UNSW-IoTraffic, 27 devices) it detects
every injected attack class (DGA, scan, exfiltration, IoT-23 malware). With service-keyed peers it **ranks**
hours almost perfectly: AUC 0.995.

**What it cannot do.** It cannot be **quiet and sensitive at once**.

| Rule | Benign deviations per device per week (median) | What happened |
|---|---|---|
| Fixed threshold 1.0 | 72 | — |
| Service-keyed peers | 29 | — |
| Per-device calibrated thresholds | ≤ 1 | only by losing DGA and exfiltration detection, and muting noisy devices |

**Therefore:** its result is an **evidence feature**. It may rank, annotate and explain. **It never raises
an alert, a notification or an enforcement action.** ADR 0023's separation matrix is unchanged by
construction.

## 2. Data plane (kernel, HomePods)

All functions named here are in `os/neuro/neuro-core/src/peerkey.rs`: `no_std`, no allocation, no float,
and bit-exact with the Python reference (`tests/peerkey.rs`).

| Step | Exactly what |
|---|---|
| **Device attribution** | source MAC → device slot (≤ 64, `el0-neuro`). Every IPv4/IPv6 address the device uses maps to the slot. |
| **DNS query** (device → port 53) | `EV_DNS` with `fp = fingerprint(fnv1a64(registered domain))`. Registered domain: the last two labels, or three when the second-to-last label has ≤ 3 characters. Remember (txid, qname) for the NX flag. |
| **DNS response** (port 53 → device) | rcode 3 on the matching query → set NX. For **every A/AAAA answer**: `NameTable::insert(dev, addr, svc_state(registered domain of the qname), now_s)`. |
| **New connection** | a TCP SYN without ACK from the device, or a UDP 5-tuple from the device idle for ≥ 120 s. |
| **Peer key** | `peer_fp(Mode::V2 { plen: 24 }, &ip, port, proto, table.lookup(dev, &ip, now_s))`, which yields `EV_FLOW { fp, bytes, conns = 1 }`. |
| **Bytes** | the IP length of every packet the device sends, in the flow or `EV_VOLUME` record. |
| **Hour close** | every UTC hour: `CMD_CLOSE_HOUR [hour of day]`. Results are 20-byte records (`abi.rs`). |

**Name table.**
- `NameTable<4096>` takes **128 KiB**: one table for all devices, 4-way sets, 32-byte entries, evicting the
  oldest entry in a full set, with a 24 h window.
- **Measured:** on UNSW (27 devices, 6 months, 2.28 M connections), the keys equal the unbounded per-device
  maps used in D1b for **100.0000%** of connections. On this testbed, no eviction changed a key.
- It stores the 64-bit FNV state of `"svc:<domain>:"`, **never a name or an address string**.

**Rule counters** are kept by the data plane, for honesty, and are not sent to the engine. They are
class, local, named and prefix. If the **prefix** share rises, names are not being seen: DoH/DoT, or
hard-coded IPs. It was 0.2% on UNSW.

## 3. Engine (`el0-neuro`): unchanged

- ABI as proposed in `os/neuro/el0-neuro/src/abi.rs`.
- Result byte 3 is renamed **`deviant`** (score ≥ 1.0). It is a flag on the evidence, not an alarm.
- Learning, Blooms and the 1,296 B per device are unchanged.

## 4. Evidence graph and UI

**Node.** A "behaviour deviation" with `{device, utc hour, driver, score (Q8), parts}`.
- It is created **only when `deviant` = 1**, so a calm hour creates no node.
- It links to the device and to the hour's flows and DNS groups.

**Never:**
- an alert, a notification, a badge count, an input to `decide()`, or a Qsecbit penalty.
- At 29–72 deviations per device per week, any of these would bury the operator.

**UI** (Observe, Investigate):
- shown in the device timeline, worded as *"behaved differently from its own history (driver: fan-out,
  score 3.4) — evidence, not an alert"*;
- it may raise the **rank** of an incident that a detection already opened;
- it never opens one.

**Explainer.** `semantic_compression.rep_cards` turns `behaviour` events into one card each, ranked below
detections:
`H1 behaviour hour=10 driver=fan_out score=3.4 (deviation from its own history; evidence, not an alert)`.

## 5. What P5 must show (e2e, QEMU then CM5)

1. Replay a capture through virtio-net, and assert **all** of the following:
   - the `EV_DNS`/`EV_FLOW` records equal `unsw_to_d1.py --peer-key v2-24 --name-table 4096` on the same
     capture;
   - the deviation nodes appear with the right driver;
   - **zero** alerts, notifications or enforcement actions come from them.
2. The separation matrix (ADR 0023) stays unchanged and green.
3. Memory: 128 KiB name table, 85 KiB `el0-neuro` `.bss`.
4. CPU per new connection is one hash and 4 compares; per DNS answer, one hash and up to 4 compares.

## 6. Not validated, and owned elsewhere

- **That the explainer is better with these cards.** The blind set is spent (`data/t0v2-results.md`), so
  this needs blind v2 before any claim.
- **An owner "this is normal" action** feeding the engine. That is learning control, which needs its own
  design.
- **A lived-in home.** P7, with consent (D2). Deakin IoT Traffic v2 stays **unopened** for the next
  pre-registered alarm attempt, if there is one.
