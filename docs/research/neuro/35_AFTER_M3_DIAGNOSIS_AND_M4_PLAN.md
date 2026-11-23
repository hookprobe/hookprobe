# 35: After M3, a diagnosis on spent data and a plan for M4 (draft, 2026-11-23)

**Status:** a planning draft, **not** a pre-registration. Every number below comes from data M3 spent:
- IoT-23 and CTU-13, dev and test;
- the UNSW dev half.

That data is dev material now. Nothing here is a confirmed result; a confirmation needs new sealed data (doc 31
stop rule).

## 1. Diagnosis: why S1 missed CTU-13

**A. More CTU-13 training data does not fix it.** The S1 recipe, run leave-one-capture-out over the whole spent
pool (1,433 windows, 517 malicious; `m4_diag.py loco`), gives:
- CTU-13 recall **0.400** (62/155);
- IoT-23 malware captures 0.815;
- Dataset-50, 52, 53 and 54 stay at 0.00–0.22.

The M3 test number (0.320, trained on 27 CTU-13 windows) was therefore not mainly a data-volume problem.

**B. Host-hour DNA v1 barely separates these bots from the lab's benign hosts** (`m4_diag.py features`):
- the best single-feature AUC is about 0.76 (`wellknown_frac`, `log_out_in_ratio`, `log_mean_dur`);
- CTU-13 bot hours look like workstation web traffic: well-known ports 0.94, HTTPS/HTTP, long sessions;
- IoT-23 bot hours look like nothing a home device does: 98% novel peers, fail ratio 1.0, about 5,600 remotes per
  hour.

**C. Mixing populations hurts the home side.** Trained on the full pool, the S1 recipe's threshold (1%
training-benign FPR) is set by the CTU-13 lab workstations. Home false alerts on the UNSW dev half rise from 0.002
to **0.558** per device-day.

**D. A source confound to fix before any reuse.** `log_pkts_per_flow` has median 0 on every CTU-13 window,
malicious and benign, against 1.65 at home. The CTU-13 export carries no packet counts. The feature is therefore a
dataset marker, not behaviour.

**Conclusion.** DNA v1 + logistic regression is a good **IoT-device** detector:
- 0.993 recall on unseen IoT-23 malware captures;
- 0.003 home false alerts per device-day on unseen devices.

It is not a detector for **general-purpose computers' C2**, which hides in ordinary web traffic. One model and one
threshold for both device classes made M3 fail on the second class and would make the home side worse if forced.

## 2. Plan for M4 (draft; becomes a pre-registration only once data is cleared and sealed)

**Split the L1 role by device class.**

| Track | Scope | Candidate | What M4 would test |
|---|---|---|---|
| **L1-IoT** | IoT and embedded devices (N0 already classes peers and devices) | the S1 recipe, trained on all spent IoT-23 + CTU-13 + UNSW material, with the confound features removed | recall ≥ 0.90 on **new sealed IoT malware captures**; ≤ 0.14/device-day on a **new home set** |
| **L1-PC** | laptops and desktops | not ready. Host-hour DNA is insufficient. It needs DNS and TLS-level features and inference-time feed values (allowed by the licence rule) | dev research only; no M4 gate yet |

**Data needed** (intel-data registry; licences as of 2026-11-18):

| Role | Candidate | Licence class / training use | Note |
|---|---|---|---|
| New sealed IoT malware | **Kitsune network attack** (includes a Mirai capture) | OPEN / yes | PCAP; needs a DNA v1 converter from PCAP (`unsw_to_dna.py` already does this) |
| New sealed IoT malware | Stratosphere MCFP IoT captures beyond the 23 in IoT-23 | UNKNOWN / unclear ("no permission needed if cited") | needs a registry decision |
| New sealed IoT malware | CICIoT2023 (Mirai, recon, brute force) | RESEARCH / unclear | needs a registry decision |
| New home benign | **Bitdefender Matter IoT** (17–22 devices × 5 captures, 2025) | OPEN / yes | CSV, not PCAP; check that the fields support DNA v1 |
| PC C2 research (dev) | DARPA OpTC (Zeek, red-team APT) | OPEN / yes | about 1 TB; dev only |
| Excluded | Deakin IoT v2 | sealed for the temporal question | unchanged |

**Methodological fixes from M3.**
1. **Leave-one-family-out, not leave-one-capture-out within a dataset.** M3's dev estimate for CTU-13 (0.815 from
   three captures) was off by 0.5.
2. **The threshold population must match the deployment population.** The 1% FPR is set on IoT-class benign
   windows, not on lab workstations.
3. **Confound screen before freezing features.** Any feature whose distribution is degenerate in one source (D) is
   dropped or rebuilt.
4. **The kernel's connection rule.** The benign side is cut with the doc 20 rule (`unsw_to_dna_conn.py --rule doc20`,
   doc 34 §2). The malicious PCAP sources (Kitsune, MCFP) can be cut the same way, closing the gap doc 34 records.

**Order.**
1. Intel-data clears licences and acquires the data. Downloads need operator approval.
2. Seal the new IoT malware and home sets by hash before any feature work.
3. Dev work on spent material only.
4. Pre-register M4 (L1-IoT).
5. One look.

## 3. What this changes now

Nothing on the device. heqk P5 stays gated (doc 34). The integer scorer and extractor plans (doc 32 §1) apply
unchanged to an L1-IoT model, if one passes M4.
