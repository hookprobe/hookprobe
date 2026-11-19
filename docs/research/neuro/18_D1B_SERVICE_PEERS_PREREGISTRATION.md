# 18 — D1b pre-registration: peers keyed by service, not by address

> 2026-11-19. **Committed before any code for this fix exists and before any number under it was
> computed.** It follows `17` (D1 failed its nuisance gate: 72 benign alarms per device per week) and
> `data/d1-results.md`.

## Hypothesis

D1's alarms are dominated by **novel peers** (65% on dev). The cause is real cloud address rotation (NTP
pool, load balancers, STUN relays) seen through the engine's exact `(IPv4, port)` peer identity.

**H:** if a peer is identified by the **service** it belongs to, the integer DNA meets the D1 nuisance gate
while still detecting the D1 attack classes.

**The engine does not change.** `dna_fixed.DNAFixed` / `el0-neuro`, the score, the threshold of 1.0 and
the learning rules all stay exactly as in D1. Only the **peer fingerprint fed to it** changes. This is a
sensor-side change: the kernel ABI keeps a `u32` peer fingerprint.

## The new peer key (fixed now)

Each flow's peer fingerprint is chosen by the first rule that applies.

**1. Infrastructure class.** One fingerprint per class and port, regardless of address:

| Class | Traffic |
|---|---|
| `ntp` | udp/123 |
| `stun` | udp or tcp 3478, 3479, 5349, 19302 |
| `dhcp` | udp/67, 68, 546, 547 |
| `lan-discovery` | mDNS 5353, SSDP 1900, LLMNR 5355, NetBIOS 137, 138 |
| `broadcast/multicast` | any broadcast or multicast destination |

Key: `fingerprint(fnv1a64("cls:" + class))`.

**2. Local peers.** A destination in RFC 1918, link-local or ULA space keeps the **exact** key used by D1:
`peer_key(ip, port)`. Lateral movement and LAN scans must stay visible.

**3. Named service.** When, in the 24 h before the flow, the device received a DNS answer (A or AAAA)
containing the destination address, the key is
`fingerprint(fnv1a64("svc:" + registered domain of the queried name + ":" + dst port))`.
- The registered domain is the same pinned rule as D1.
- The most recent answer wins.
- Mapping state is per device, capped at 4,096 address entries with oldest-first eviction. This bounds the
  sensor-side cost, which must be reported.

**4. Unnamed public peer.** Otherwise the key is the network block plus the port:
`fingerprint(fnv1a64("net:" + /P prefix + ":" + dst port))`.
- IPv4: `P` ∈ {24, 16}, chosen on dev.
- IPv6: /48.

The DNS events (queries, NXDOMAIN) are unchanged from D1.

## Variants and how one is chosen

| Variant | Rules on |
|---|---|
| **V1** | 2, 3, 4 (no infrastructure classes) |
| **V2** | 1, 2, 3, 4 |

Each variant is tried with `P` ∈ {24, 16}, giving **four configurations**.

**Choice on UNSW-IoTraffic dev, the D1 split unchanged.** The selected configuration is the one that:
1. reaches a median ≤ 1 benign alarm per device per week (devices with ≥ 7 active dev days, as in D1, A6);
2. keeps detection ≥ 0.9 for **each** of the four D1 attack classes;
3. among those, has the fewest rules (V1 before V2), then the larger `P` (/24 before /16).

If none qualifies, the hypothesis is **rejected on dev** and nothing is tested.

**Disclosure:** UNSW dev was already looked at under the D1 key, and its alarm drivers were inspected. Dev
is therefore not a clean estimate. It is used only to choose.

## Attacks under the new key (as D1, addendum A5)

| Attack | How it is keyed |
|---|---|
| Scan | LAN peers: exact keys (rule 2), unchanged |
| Exfiltration | the new external peer has no DNS answer, so it gets the prefix key (rule 4) |
| DGA | DNS events: unchanged |
| IoT-23 malicious hours | conn logs carry no names, so rule 4 applies (IoT-23 dev split for dev, test split for test) |

**Known blind spot:** an attacker that resolves a name under an already-learned registered domain, and uses
an already-seen port, is invisible to the novelty term by design. Abuse of a cloud host the device already
talks to is out of scope for this tier. It is reported, not hidden.

## Confirmation (the gate)

**Primary: a fresh dataset never opened by this project.** It is chosen by these criteria, **before**
download:
- raw packet captures that include DNS;
- ≥ 10 consumer IoT devices, ≥ 14 days;
- a licence that permits research use and publication of derived figures;
- not the UNSW 2016–17 testbed (shared devices and period).

Order of preference:
1. **A consented HookProbe home network.** Plan `14`, item D2, with flows plus DNS answers. A lived-in home
   is the deployment target.
2. A public dataset meeting the criteria, licence checked first.

**The candidate's name, licence and digest are recorded in this file in a commit before its data is
read.**

On the primary dataset:
- the frozen configuration runs once;
- the split is per device: first 50% of active days for learning, unscored; last 50% scored;
- **Gate:** median ≤ 1 benign alarm per device per week, with detection ≥ 0.9 per attack class (same
  overlays). Both readings (the median, and per device) are reported, as in D1.

**Secondary: UNSW-IoTraffic test.** It is run once with the frozen configuration and reported, but it
**cannot pass the gate on its own**: its aggregate D1 result is known (contaminated).

## Decisions

- **Both pass:** service-keyed peers become the P5 integration input. The DNA is cleared as an alarm
  source **on top of** `17`'s evidence-only status, still behind the field pilot (P7).
- **Primary fails:** the temporal tier stays evidence-only (as decided in `17`). No further peer-key
  variants are tried on the same data.
- In all cases, report:
  - the alarm drivers;
  - the sensor-side cost (mapping table bytes, lookups per flow);
  - the share of public flows that resolved to a name versus fell back to a prefix.

## What this needs

1. **Converter:** parse DNS answers (A/AAAA) and keep the per-device address → name table. Emit the new
   keys. Add self-tests for each rule.
2. **`d1_analysis.py`:** a `--peer-key` mode. No other change.
3. **The fresh dataset (primary gate):** for the HookProbe home network, the owner's consent (D2) and a
   flow + DNS-answer export; otherwise a licence-checked public set.

## Primary dataset, chosen (2026-11-19, before download; only the public metadata has been read)

**Deakin IoT Traffic Dataset (D-IoT).**
- Authors: Pasquini, Vasa, Habibi Gharakheili, Logothetis, Chambers, Tran.
- Deakin University, Figshare article 28013234, **version 2** (published 2025-02-05), DOI
  `10.26187/deakin.28013234.v2`, **CC BY 4.0**.

**How it meets the criteria:**
- 24 consumer IoT devices (19 types).
- Device-filtered, full-packet captures (`IoT_<date>.pcap`): 150 daily files, 2023-05-15 → 2024-05-29,
  38.29 GB in all.
- The captures keep every layer, so DNS is included.
- A **different testbed and period** from UNSW 2016–17. One author is shared.
- It ships interaction metadata (`activeInteractions.csv`, `passiveInteractions.csv`).

**Files used:** only the 150 `IoT_*.pcap` files plus the CSVs (`macAddresses.csv` gives the device
identity). The 88 `pcapFull` files, which carry traffic from 36 non-IoT devices, are **not downloaded**.

**Digests:** `data/d1b-deakin-manifest.tsv` lists the name, size and MD5 of every file to be used, taken from
Figshare. Every downloaded file must match its line before it is converted.

**Caveat, as with D1:** the description says "a controlled environment under normal operating
conditions". This is a lab with scripted interactions, not a lived-in home.

**Note, found during download:** Figshare lists 31 of the `IoT_*.pcap` files twice, with identical name,
size and MD5. The manifest above therefore holds **119 unique daily captures**, matching the dataset's
"119 days" (31.56 GB). The duplicates are downloaded once.

## Implementation (committed before any D1b number was computed)

- **`unsw_to_d1.py --peer-key {exact, v1-24, v1-16, v2-24, v2-16}`.**
  - It parses DNS answers (A/AAAA, with name compression) into a per-device address → registered-domain
    table: 24 h window, 4,096 entries per device, oldest-first eviction.
  - It applies the rule order above, and reports the rule counts and the largest table size.
  - `exact` is D1's key.
  - Self-tests: 10 new rule checks, all passing.
- **`d1_analysis.py --phase dna --period {dev, test} --split {d1, half} --peer-key …`.**
  - It runs the DNA alone with the D1 overlays keyed by the same rule. Overlays carry no transport, so
    class matching is by port only.
  - `--split half` is the confirmation split: the first 50% of active days learn, the last 50% are scored.
