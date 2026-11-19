# D1 results: the integer temporal engine on 6 months of real IoT traffic (UNSW-IoTraffic)

> 2026-11-19. Pre-registration: `../17_D1_PREREGISTRATION.md`, including its analysis addendum, committed
> before any score was computed (PR #1342). Script: `tools/neuro-research/d1_analysis.py`.
> Raw outputs: `d1-dev.{txt,json}` and `d1-test.{txt,json}`. **The test portion was opened once.**

## Data

- **Recording:** UNSW-IoTraffic, 27 devices, 2016-09-22 → 2017-04-13.
- **Converted:** 95.5 M packets → 37,555 device-hours. The conversion took 3.6 min.
- **Held out by the rule:** 7 devices (see addendum A3).
- **Counted in medians:** 21 devices with ≥ 7 active days in the period.
- **Spliced attacks:**
  - dev: 9 IoT-23 infected scenarios, from its dev split;
  - test: 11 IoT-23 infected scenarios, from its test split;
  - test onsets: 192 DGA, 199 scan, 198 exfiltration and 192 IoT-23.

## Results

| | Dev | **Test** | Gate / rule |
|---|---|---|---|
| **Q1** DNA benign alarms per device per week (median, 21 devices) | 46.8 | **72.0** | ≤ 1 ❌ |
| Devices above 1 per week | 21 / 21 | **19 / 21** | — |
| **Q2** `q_min` ∈ {3, 5, 10, 20} | identical to no rule at every value; none qualifies | not applied | ≤ 1 per week with DGA detection ≥ 0.9 ❌ |
| **Q3** incident detection within the attack hours (DNA, threshold 1.0) | DGA 1.00 | **DGA, scan, exfiltration, IoT-23: all 1.00**; held-out devices 1.00 | — |
| Q3 hour-level AUC (DNA) | 0.910 | **0.884** | — |
| **Q4** learned cell B: AUC | 0.814 (ridge 100) | **0.808** | ≥ DNA + 0.02 ❌ |
| Q4 B at its dev-calibrated threshold | — | median 0.0 per week; **detection 0.57** | — |

Test, alarms per device per week (DNA): 0.0 to 162. The quiet devices are a smart scale, a weather
station and a smoke alarm. The worst are TP-Link camera (162), August doorbell (159), Samsung camera (150),
LiFX bulb (146) and SmartThings (133).

## Decision (by the pre-registered rule)

- **Q1 fails, and Q2 does not fix it.** So the **temporal tier does not ship as an alarm source.** It stays
  an **evidence feature** with no alarms of its own, until a fix passes a new pre-registration.
- **Q4:** the DNA stays. B is quieter only because its threshold trades away 43% of detections, and its AUC
  is 0.08 lower.
- The engine's detection side is fine: every spliced attack class was caught on real timelines, including
  on held-out devices. **The problem is purely nuisance.**

## Why (diagnosed on dev and history data only, after the dev run, before the test run)

**Alarm drivers on dev, all 21 devices:**

| Driver | Alarms |
|---|---|
| novel peers | **2,860 (65%)** |
| volume | 660 |
| fan-out | 451 |
| activity | 270 |
| DNS | 157 |

Several devices alarm in **every** dev hour (LiFX, TP-Link camera, August doorbell), with about 11 of 13
peers new each hour.

**The raw packets in the history period show real cloud behaviour, not a conversion artefact:**

| Device | Counted connections | What the churn is |
|---|---|---|
| LiFX bulb | 19,489 | 13,005 are **NTP to the public pool** (udp/123), which hands out rotating server IPs |
| SmartThings | 7,804 | 7,527 are NTP |
| August doorbell | 581,077 | TCP/443 connections to **281 load-balanced cloud addresses** |
| TP-Link camera | — | **STUN/P2P relays** (udp/3478) plus port-8089 services |

**The root cause is a design weakness.** The engine's peer identity is the exact `(IPv4, port)`, so
anycast, NTP-pool and load-balancer rotation look like new destinations every hour. The guarded learning
then refuses to admit those peers in alarming hours, which keeps them novel. The persistence rule (6
sightings) cannot keep up with hundreds of rotating addresses.

## Fix direction (not tested — each needs its own pre-registration and a fresh split)

1. **Peer = service, not address.** Key peers on the DNS name the device resolved for them. This is the
   on-device resolver/flow join that dnsXai already has. Fall back to the network block, such as /24 or the
   ASN, plus the port.
2. **Infrastructure allowances:** NTP (udp/123), STUN (3478) and DHCP/mDNS/SSDP are scored as one peer
   each per port class, not per address.
3. **Recalibrate the alarm threshold** per device class, or use a rate-limited alarm budget. D1 fixed the
   threshold at 1.0 on purpose; any recalibration must be chosen on dev.

**Caveat:** the testbed has no people in it, so a lived-in home will be noisier, not quieter. The cloud
rotation observed here is the dominant effect either way.
