# ADR 0042 — Wi-Fi as a SECURITY SURFACE (WIDS): own the radio, not the blob

- **Status:** 🟡 Proposed (direction accepted 2026-07-17; implementation phased — see Validation)
- **Date:** 2026-07-17
- **Supersedes/extends:** none. **Depends on:** ADR 0034 (adaptive Wi-Fi, esp. Extension RC-DFS),
  ADR 0023 (enforcement separation), ADR 0003 (capabilities), ADR 0002 (trust-nothing-unsigned).

## Context — the DFS dead-end forced a better question

ADR 0034's Extension **RC-DFS** closed the DFS question empirically: on the onboard brcmfmac
BCM43455 (Pi4/CM5), DFS-AP **cannot be made to work**. Every lever was tested on real silicon and
failed — `iw reg set`, the #6669-fixed Infineon firmware `7.45.286`, Infineon's fuller CLM blob, and
an NVRAM `ccode=RO` override. The firmware stays locked at `country 99: DFS-UNSET` and flags DFS
channels `NO-IR RADAR` (an AP may not beacon). The only untested path is binary-patching the firmware
(nexmon-style), which is unsigned, unmaintainable, and a regulatory liability.

That result is worth taking seriously, because it exposes the strategic error in the original goal.
**Chasing DFS was chasing parity with a home router** — more 80 MHz blocks, slightly less contention.
Even if it had worked, it would have differentiated us from nothing: every consumer AP has DFS.

The right question is not "how do we get more Wi-Fi channels?" but **"why does a SOC appliance have a
radio at all?"** — and the honest answer is that a radio is a *sensor*, not just an access port. We
already treat every wire as a monitored surface (Senzorium/NAPSE); the air is the one surface we
currently transmit on but never watch. Competitors (FortiSOC, Sentinel, Defender XDR) have no radio at
all; consumer APs have a radio but no SOC. **The overlap — a signed, intent-operated SOC that also
sees the RF layer — is ours to take.** That is a differentiator; DFS is a checkbox.

This ADR therefore makes two decisions: *what* we build (Wi-Fi as a monitored security surface), and
*how we get the hardware for it* (own the radio, not the blob).

## Decision

### D1 — The air is a monitored surface, feeding the ONE evidence graph

Wi-Fi telemetry is not a Wi-Fi feature; it is **Senzorium observation of a new medium**. 802.11
management/control frames (beacon, probe req/resp, auth, assoc, deauth, disassoc) are captured via a
monitor-mode radio, normalized into the **same common event schema** as every wired event, and folded
into the **same evidence graph** (`Device → Interface → … → Threat → Incident`). No parallel "Wi-Fi
console," no separate data model — that would violate "one system." Observed BSSIDs/SSIDs/stations
become ordinary graph nodes; Wi-Fi detections become ordinary detections in **Detect**, investigable
in **Investigate**, exactly like a port scan. This is the whole point: an operator asks *"what
happened"* and the answer spans wire and air in one timeline.

### D2 — Radio capability tiers (manifest-driven; code NEVER asks "is this a Pi?")

Per ADR 0003's invariant (capabilities, not branches), radio ability is expressed as **capabilities
granted by the Platform Manifest**, resolved once at first boot:

| Capability | Meaning | Onboard brcmfmac (base) | SoftMAC (ath9k/ath10k/ath11k, mt76) |
|---|---|---|---|
| `wifi_ap` | can serve an AP | ✅ (UNII-1 36–48 only, VHT80) | ✅ (full band) |
| `wifi_monitor` | monitor mode + radiotap capture | ❌ **never** (FullMAC; needs nexmon) | ✅ |
| `wifi_dfs` | DFS-AP with real CAC/radar | ❌ **never** (proven, ADR 0034 RC-DFS) | ✅ |
| `wifi_inject` | frame injection (test harness only, ADR 0020 ROE) | ❌ | ✅ (gated) |
| `wifi6` / `wifi_6e` | HE / 6 GHz | ❌ | ✅ (radio-dependent) |

Mission Control renders, greys-with-reason, or hides purely from these tokens: on a base Pi the WIDS
workspace panel is **greyed with the honest reason** *"this radio cannot monitor — add a supported
Wi-Fi sensor radio"*, never silently absent and never faked. `wifi_dfs` is **hard-denied for the
brcmfmac radio class** by construction (RC-DFS), so the optimizer never probes it (this supersedes
ADR 0034's D30 "test once and learn" for this radio class — the answer is known).

### D3 — Own the RADIO, not the blob (the hardware decision)

We do **not** patch Broadcom firmware to buy capability. We add a radio that has the capability
natively, with a **mainline, signed, maintained** driver:

- **Base SKU** (Pi 4 / CM5, onboard brcmfmac): `wifi_ap` only — UNII-1/VHT80 (~450 Mbit/s). Honest,
  works, ships today. **No monitor, no DFS.**
- **Pro/appliance SKU:** a **SoftMAC/mac80211 radio** (USB or M.2 — ath9k/ath10k/ath11k or mt76
  class) → grants `wifi_monitor` + `wifi_dfs` + Wi-Fi 6 natively. Real CAC, real radiotap, real
  injection, no reverse-engineering, no unsigned blob, no compliance exposure.
- **The design test holds:** adding a supported radio = **one entry in `platforms/*.yaml`** (a
  known-good driver/chipset row granting the tokens above). No UI, installer, or API change.

A dedicated sensor radio is also the *architecturally* correct split: the onboard radio **serves** the
AP while the SoftMAC radio **watches** the air. One radio cannot beacon on ch40 and hop channels
scanning for rogues at the same time — so `wifi_monitor` implies a *second* radio, not a mode switch
on the AP radio.

### D4 — The WIDS detection catalogue (rule block `1000200–1000215`)

Detections are ordinary NAPSE detectors over normalized 802.11 frames (new rule block, following the
existing convention — L1/L2 `1000030–33`, host-EDR `1000100–115`):

| Rule | Detection | Signal |
|---|---|---|
| `1000200` | **Rogue AP** | a BSSID beaconing in our space that is not in the known-good/authorized set |
| `1000201` | **Evil twin** | **our** SSID beaconing from a foreign BSSID (or mismatched security/channel) |
| `1000202` | **Deauth/disassoc flood** | deauth/disassoc rate from a source far above baseline (the classic client-eviction attack) |
| `1000203` | **Karma / MANA** | an AP probe-responding to *any* requested SSID (responds to SSIDs that don't exist) |
| `1000204` | **Beacon flood** | implausible count of distinct BSSIDs appearing (SSID-spam / scanner confusion) |
| `1000205` | **PMKID / handshake harvest** | association patterns consistent with PMKID capture or forced re-handshake |
| `1000206` | **BSSID/MAC impersonation** | our BSSID seen with a mismatched fingerprint (sequence/beacon-interval/capability drift) |
| `1000207` | **Open-AP impersonation / downgrade** | our SSID advertised open or with weakened cipher suite |

Each fires an ordinary detection → evidence (frames retained per ADR 0003 tiering, bounded like every
other capture) → incident, with the standard AI explanation panel (*why · confidence · evidence ·
related events*). Rogue/evil-twin need an **authorized-BSSID baseline**, which the box already has
grounds to learn (it knows its own AP identity from the signed manifest) plus operator intent.

### D5 — WIDS is OBSERVE-ONLY. No deauth containment. Ever. (ADR 0023 compliance)

**We will not ship RF "containment"** (deauthing a rogue AP or its clients), even though most WIPS
products do. Three independent reasons, any one sufficient:

1. **It is itself an attack.** Transmitting deauth frames at a third party's AP/clients is a DoS. We
   do not ship attack tooling that runs autonomously in the field (ADR 0020 confines offensive probes
   to a DUT under ROE).
2. **It is illegal in many jurisdictions.** Regulators have levied substantial fines for Wi-Fi
   deauth-blocking. Shipping it as a default would expose operators to legal risk we created.
3. **It violates our hard rule.** ADR 0023: *a legitimate connection must ALWAYS pass*, and only
   **resource-reality** (not identity/suspicion) may trigger enforcement. A "rogue AP" verdict is
   *suspicion about identity* — precisely the class barred from the enforcement path. A misclassified
   neighbour's AP would have us attacking an innocent third party.

The sanctioned responses are: **alert + evidence + explain**, and — for clients on **our own** AP —
ordinary existing NAC/quarantine on **our own** network (a policy decision about who we serve, not an
RF attack on someone else). This restraint is itself a selling point: we detect the attack and prove
it, without becoming one.

**Hard constraint (security-audit tightening, 2026-07-17):** a WIDS detection is **observe-only
end-to-end** and may **never** be a direct detection→enforce edge — not even the sanctioned on-AP
NAC/quarantine above. A "rogue AP"/"PMKID-harvest"/"impersonation" verdict is *identity/suspicion*,
which ADR 0023 bars from the enforcement path; a misclassified neighbour would otherwise get a
legitimate client on our own AP evicted. Any NAC/quarantine that a WIDS finding *informs* must be an
independent operator or AEGIS-reconciler **policy** decision, routed through the deterministic gate
(contract C9: AI proposes, the gate enforces) with the "legitimate connection ALWAYS passes" invariant
intact — never wired straight from a `1000200–1000215` detector to a drop/evict.

### D6 — Nexmon: a prototype instrument, never a shipped artifact

Nexmon (brcmfmac firmware patching) may be used **only** on a lab DUT to prototype detector logic
before a SoftMAC radio is sourced. It is **barred from any image** (Red gate): unsigned blob (ADR
0002), per-firmware-version RE burden, and regulatory exposure. No release may depend on it; a
detector prototyped under nexmon must be re-validated on a mainline SoftMAC radio before it ships.

### D7 — Honest capability messaging (no faked WIDS on a base box)

Because base hardware genuinely cannot monitor, **the WIDS story must never be implied on a base
SKU.** The manifest gates it; the UI greys it with the reason and the remedy; marketing copy for the
base tier does not claim RF monitoring. Overclaiming here would be exactly the failure mode this
project keeps catching (spec-says-X-hardware-does-Y).

## Validation plan (gate ladder)

- **T1 (pure):** capability resolution (`wifi_monitor`/`wifi_dfs` granted only for known-good SoftMAC
  chipsets; **hard-denied for brcmfmac**), detector unit tests over synthetic radiotap/802.11 frames
  (rogue/evil-twin/deauth-flood/karma fixtures), UI gate-rendering tests (greyed-with-reason on base).
- **T2/T3:** detector runs headless over a recorded pcap corpus; no radio needed.
- **T4 (metal, gated on hardware):** a SoftMAC radio in monitor mode alongside the onboard AP, with
  attacks staged **only** against our own DUT AP inside the ADR 0020 ROE (netns/dedicated link — the
  standing constraint that L2/RF floods must never touch the shared mgmt link applies fully here; a
  deauth flood on the operator's own link would DoS their SSH).
- **Release gate:** ADR 0023's separation matrix gains WIDS rows proving **every** Wi-Fi detector is
  observe-only (no drop/deauth path exists), and that a legitimate client on our AP is never evicted.

## Consequences / honest limits

- **Nothing here ships on base hardware.** This ADR buys a differentiator only with a radio we do not
  yet source — the immediate deliverable is the *decision + the capability seam*, not a feature.
- **A radio must be selected and validated** (chipset, driver, monitor+AP concurrency, thermals, USB
  vs M.2, cost). That is real BOM work and is the true critical path — not software.
- **Rogue/evil-twin detection needs a baseline** and will produce false positives in dense RF (a
  neighbour's AP is not a rogue). Observe-only (D5) makes an FP *cheap* — an alert, never an eviction
  — which is exactly why the restraint is affordable.
- **Channel-hopping monitor sees a duty-cycled slice of the air**; detection is probabilistic, and the
  UI must say so (confidence, dwell time), never imply full coverage.
- **DFS remains closed on base** (ADR 0034 RC-DFS). `wifi_dfs` arrives with the SoftMAC radio or not
  at all.

## Proven vs pending (brutally honest)

| Item | Status |
|---|---|
| DFS-AP impossible on brcmfmac (motivating fact) | ✅ **Proven on metal** across every lever (ADR 0034 RC-DFS) |
| Direction: Wi-Fi as security surface, not DFS parity | ✅ Accepted (operator, 2026-07-17) |
| "Own the radio, not the blob" (no firmware patching) | ✅ Decided (D3/D6) |
| Observe-only WIDS, no deauth containment | ✅ Decided (D5) — binds to the ADR 0023 matrix |
| Radio capability tokens in the manifest schema | 🔴 Not built (D2 seam) |
| WIDS detectors `1000200–1000215` | 🔴 Not built (spec only; T1 fixtures first) |
| SoftMAC radio selected/validated (BOM) | 🔴 **Not started — the real critical path** |
| Monitor+AP concurrency on real hardware | 🔴 Unproven (needs the radio) |

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The WIDS-as-observation posture and the detector catalogue (`1000200–15`, observe-only, no deauth) are portable Rust; monitor-mode 802.11 / radiotap capture depends on heqk gaining a mac80211-equivalent monitor surface — a real hardware/driver gap on the CYW43455. "Own the radio not the blob" aligns with heqk's ethos. → **Parallel WiFi track**.
