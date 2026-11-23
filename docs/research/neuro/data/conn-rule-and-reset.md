# Connection-rule re-measure (doc 32 §2) and N0 reset behaviour, 2026-11-23

Both measurements are descriptive and refit nothing. Models and thresholds are the frozen M3 ones (`m3_run.py`).

## 1. DNA v1 home false alerts: Zeek-like rule vs the kernel's doc 20 rule

**Converter.** `bench/unsw_to_dna_conn.py` is generated from the frozen `unsw_to_dna.py` `one()` with only the
connection rule parameterised:
- `--rule zeek` reproduces the frozen M3 home file exactly: sorted multiset equal, 15,413 = 15,413 lines;
- `--rule doc20`: every TCP SYN without ACK starts a connection, with no TCP idle split (a 24 h guard bounds
  memory); UDP and ICMP use 120 s idle.

**Approximations.**
- Inbound SYNs also start connections. DNA counts inbound sources; N0 counts only device-sent SYNs.
- ICMP is kept, although doc 20 does not count it.

**Second half (spent by M3, so used here freely):**

```
UNSW second half: windows (>= 3 events) zeek 14360, doc20 13934; devices 27 / 27

| system | home FA/device-day, Zeek rule | home FA/device-day, doc 20 rule | worst device (doc 20) |
|---|---|---|---|
| S1 notify | 0.003 | 0.000 | NetatmoWeatherStation 0.00 |
| S2 L0-gated | 0.042 | 0.043 | CanaryCamera 8.68 |
| S3 act | 0.002 | 0.000 | NetatmoWeatherStation 0.00 |
| logreg 32 | 0.008 | 0.017 | TribySpeaker 0.27 |
| rules any (ungated) | 7.660 | 6.051 | AugustDoorBell 22.11 |

paired windows: 13932. Feature shift doc20 - zeek (median, p90 |diff|), sorted by p90:
| feature | median diff | p90 abs diff |
|---|---|---|
| log_period_s | +0.000 | 4.158 |
| log_mean_dur | +0.000 | 2.737 |
| port_entropy | +0.000 | 0.486 |
| log_pkts_per_flow | +0.000 | 0.455 |
| log_flows | +0.000 | 0.357 |
| periodic_cv | +0.000 | 0.265 |
| icmp_frac | +0.000 | 0.176 |
| top_port_share | +0.000 | 0.143 |
| tcp_frac | +0.000 | 0.139 |
| udp_frac | +0.000 | 0.122 |
| wellknown_frac | +0.000 | 0.102 |
| log_max_per_min | +0.000 | 0.095 |
```

**First half (dev):**

```
UNSW first half (dev): windows (>= 3 events) zeek 15521, doc20 15457; devices 27 / 27

| system | home FA/device-day, Zeek rule | home FA/device-day, doc 20 rule | worst device (doc 20) |
|---|---|---|---|
| S1 notify | 0.002 | 0.000 | WithingsSmartScale 0.00 |
| S2 L0-gated | 0.071 | 0.073 | NestDropCam 4.36 |
| S3 act | 0.000 | 0.000 | WithingsSmartScale 0.00 |
| logreg 32 | 0.031 | 0.030 | TribySpeaker 0.46 |
| rules any (ungated) | 5.434 | 3.368 | SamsungSmartThings 18.36 |
```

**Reading.**
- **The kernel's rule does not raise home false alerts.**
  - S1 goes from 0.002–0.003 to 0.000 per device-day; S3 likewise.
  - S2 is unchanged (0.042 → 0.043, 0.071 → 0.073).
  - The ungated rules drop (7.66 → 6.05, 5.43 → 3.37), because long TCP sessions are no longer split by idle time.
- Median feature shift is 0 for every feature. The tails move in `log_period_s`, `log_mean_dur`, port entropy and
  packets per flow, which are the duration and periodicity features the rule affects.

**Limit.** Only the benign side can be re-cut. The malicious datasets exist only as Zeek `conn.log`, so recall under
the doc 20 rule is **not measured**. Any future L1 calibrated on Zeek-derived data must be re-validated on traffic
cut by `neuro-dp` itself.

**Hashes.**

| File | SHA-256 |
|---|---|
| `unsw_doc20_first.jsonl` | `e4dc74154894893ff5faabd1ef9516ade153ba7fa8337ad80a4f3c792765ae9b` |
| `unsw_doc20_second.jsonl` | `2106476c1b03c782bc9f7ba172872fceeea433120e9bbd348ab0ad1fb2c23087` |
| `unsw_zeek_second.jsonl` (= frozen `unsw_m3_second.jsonl` as a multiset) | `2b61e8fc…` (line order differs) |
| `unsw_dev_v3.jsonl` (frozen dev half, Zeek rule) | `87242aadc3894d1141ec39cd3b57cc6d9c27629e746cd1219a5fed43b431b46e` |

## 2. N0 after an el0-neuro reset (metal fault injection, heqk #1487)

`reset_sim.py` uses `dna_fixed.DNAFixed`, which is bit-exact with `neuro-core`, fed as in `d1_analysis`, on UNSW D1
data (20 devices with ≥ 28 active days).

**Method.**
- Each device is run once uninterrupted.
- It is run again with a fresh engine (memory lost) from active day *k*.
- Deviant = score ≥ 1.0. Device-hours are counted from the reset.

| Hours since reset | k = 7: never reset → after reset | k = 14 | k = 21 |
|---|---|---|---|
| 0–24 h | 0.285 → 0.295 | 0.432 → 0.290 | 0.435 → 0.327 |
| 24–72 h | 0.265 → 0.081 | 0.381 → 0.127 | 0.362 → 0.098 |
| 72–168 h | 0.252 → 0.187 | 0.378 → 0.255 | 0.431 → 0.367 |
| 168–336 h | 0.315 → 0.275 | 0.424 → 0.375 | 0.483 → 0.456 |
| ≥ 336 h | 0.484 → 0.482 | 0.482 → 0.493 | 0.485 → 0.523 |

**Reading.**
- **After a reset the engine flags fewer deviant hours, not more.** The cold-slot widening (`COLD_WIDEN_Q8`, the
  Phase 0b fix) raises thresholds while slots have fewer than `SLOT_MIN` samples.
- The deficit is deepest at 24–72 h (about 0.3× the uninterrupted rate) and closes within about two weeks (≥ 0.87×
  by 168–336 h, about 1.0× after 336 h).
- **Consequence.** A reset is not a false-alarm risk. It is a **sensitivity gap of about one to two weeks**, during
  which "behaved differently from its own history" has little history behind it. Doc 34 proposes how evidence should
  say so.
