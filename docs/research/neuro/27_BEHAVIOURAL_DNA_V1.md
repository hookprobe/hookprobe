# 27: Behavioural DNA v1, the per-device behaviour record (specification draft, 2026-11-22)

**Status: PROPOSED.**
- The feature extractor is implemented as Python reference code (`tools/neuro-research/bench/dna_features.py`) and
  feeds the benchmark (doc 28).
- The on-device Rust record and the rolling baseline are not implemented yet.
- This document fixes the format, so that the benchmark, the training data and the device share one definition.

## 1. Purpose and boundary

DNA is **evidence, never a verdict** (doc 20). It summarises what a device did in a window and how far that is
from the device's own history. Verdicts come from L0 rules and the supervised classifier (doc 28). The explainer
only describes. **Nothing in DNA can change enforcement directly**; the policy compiler (doc 29) consumes verdicts.

## 2. Window and identity

| Field | Type | Notes |
|---|---|---|
| `device_id` | u32 | gateway-local id, stable across DHCP. Bound to MAC + first-seen; never a raw IP in exported records. |
| `role` | u8 | enum from the device-identity layer (camera, NAS, TV, laptop, …; 0 = unknown). Owner-confirmed roles are flagged. |
| `window_start` | u32 | epoch minutes. |
| `window_len` | u8 | minutes. v1 = **60**; 10-minute windows are a v1.1 candidate (the literature favours 1–10 minutes for scans and bursts). |
| `dna_version` | u8 | **1** = the 32 features below, in this order. Any change bumps the version; old records are never reinterpreted. |

## 3. Feature vector v1 (32 features)

All features come from flow metadata plus remote context. **No payload is used.** Raw values are float on the
reference path. The device record stores each feature quantised to **u8** with a per-feature fixed scale (§5).

| # | Feature | Meaning |
|---|---|---|
| 0 | `log_flows` | log1p flow count |
| 1 | `out_frac` | share of flows the device initiated |
| 2 | `log_remotes` | log1p distinct peers |
| 3 | `log_dst_ports` | log1p distinct destination ports (outbound) |
| 4 | `port_entropy` | Shannon entropy of destination ports |
| 5 | `top_port_share` | share of the most-used port |
| 6 | `fail_ratio` | share of flows in failed states (S0, REJ, RSTOS0, SH, SHR, RSTRH, OTH) |
| 7–9 | `log_bytes_out`, `log_bytes_in`, `log_out_in_ratio` | volume and direction |
| 10–11 | `log_mean_dur`, `log_pkts_per_flow` | flow shape |
| 12–14 | `tcp_frac`, `udp_frac`, `icmp_frac` | protocol mix |
| 15 | `wellknown_frac` | share of ports below 1024 |
| 16–21 | `telnet_frac`, `ssh_frac`, `smb_frac`, `web_frac`, `dns_frac`, `ntp_frac` | service mix: worm, brute-force and lateral-movement cues |
| 22–23 | `periodic_cv`, `log_period_s` | lowest inter-arrival CV and its period, over the top-3 peers (beaconing) |
| 24 | `log_max_per_min` | peak flows per minute (bursts) |
| 25 | `novel_pair_frac` | share of (device, peer) pairs absent from the 24 h baseline |
| 26–29 | `warninglist_frac`, `unrouted_frac`, `log_countries`, `log_asns` | remote context (iptoasn + MISP warninglists, via pseudonym-keyed lookup) |
| 30 | `lan_peer_frac` | share of LAN peers (lateral) |
| 31 | `log_inbound_sources` | distinct inbound initiators (being scanned) |

**Planned for v2** (needs DNS events on the window path): NXDOMAIN rate, distinct new registered domains, label
entropy (DGA), and DNS-to-flow consistency.

## 4. Deviation, confidence, provenance, expiry

**Per-device baseline (rolling).**
- For each feature: a streaming median and IQR (P² quantile estimators, or a 3-bucket EWMA approximation), plus an
  EWMA mean and variance. That is 4 × f16 = 8 bytes per feature, 256 bytes per device.
- **The baseline is frozen while the device is under an active alert.** An attacker must not be able to teach
  their behaviour as normal (poisoning; NIST AI 100-2).

**Deviation.** `dev_i = (x_i − median_i) / max(IQR_i, ε)` per feature, clipped to ±8 and stored as i8. The
record also carries the top-3 deviating feature indices.

**Confidence.**
- Each record carries `history_windows`, the number of windows behind the baseline (u16).
- Below 24 windows, deviations are marked **low-confidence**: new devices are not judged against a thin baseline.

**Provenance.**
- `sensor_build` (u32): the hash prefix of the extractor version.
- `context_lookup_id` (u32): the hash prefix of the lookup build used for remote context.
- `flags`: owner-confirmed role, baseline frozen, low confidence, and any `licence_caveat` source present.
  **Records carrying a licence_caveat source are never exported for training.**

**Expiry.**
- Records live **7 days** on the device by default, in a ring buffer.
- The baseline ages out with a 14-day half-life, so firmware updates and new routines become normal over about
  two weeks, unless the device is under alert.

## 5. On-device record size (CM5)

| Part | Bytes |
|---|---|
| header (`device_id`, `role`, `window_start`, `len`, `version`, `flags`, `history`, two provenance ids) | 20 |
| features, u8 × 32 | 32 |
| deviations, i8 × 32 | 32 |
| top-3 deviating indices + scores | 6 |
| **record total** | **90** (padded to 96) |
| per-device rolling baseline, 32 × 8 B | 256 |
| per-device peer set (existing NameTable / peerkey, shared 128 KiB table) | shared |

**Budget at 256 devices:**
- baselines: 64 KiB;
- 7 days × 24 records × 96 B ≈ 16 KiB per device, so 4 MiB for 7 days of history for all devices.

History therefore lives **outside** heqk's 4 MiB EL0 window, in the companion or storage tier. Only the current
record and the baselines need to be resident: about 90 KiB.

**CPU.** One streaming pass per flow, with O(1) updates except the per-peer inter-arrival buffer (capped at 400
timestamps per peer per window). Profiling on CM5 is still to do (milestone M2 in doc 30).

## 6. What DNA is not

- Not an identity fingerprint for tracking people.
- Not exported raw. Exports use pseudonymised peers (the intel-data rule).
- Never input to enforcement without passing through a verdict and the signed policy compiler (doc 29).
