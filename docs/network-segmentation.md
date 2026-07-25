# Network Segmentation — beyond MAC filtering (investigation + model)

> **Thesis:** A MAC address is **not an identity.** Segmenting a network by MAC (OUI
> classification + `dl_src` OpenFlow flows, as V1 does) works only for stable-OUI IoT and
> fails for every modern client. HookProbe OS segments by **layered identity**: a
> cryptographic credential (802.1X) where possible, behavioural fingerprint where not, and
> a low-trust onboarding segment for the unknown — with continuous re-evaluation. This doc
> is the investigation behind `crate::fabric` and the roadmap past it.

Canonical fabric model + the two planes (L2 OVS switching / L3 VRF routing separation) live
in `docs/network-fabric.md` / report §8.17. This doc is specifically about **how a device is
assigned to a segment** — the identity problem.

---

## 1. Why MAC filtering is broken

The V1 model (`shared/network/segmentation.py` OUI tables → `vlan_manager.py` `priority=200,dl_src=<mac>,actions=mod_vlan_vid:<vlan>` flows) assumes a MAC ↔ device ↔ trust mapping. Every link in that chain is weak:

| Failure | Detail |
|---|---|
| **MAC randomization** | iOS/Android/Windows default to a per-SSID *random* MAC; many rotate it periodically. The **locally-administered bit** (`0x02` in octet 0) is set → there is **no real OUI** to classify, and the `dl_src` flow goes stale on every rotation. The device reappears as "new/unknown" and is dumped in quarantine — a constant false-positive churn. |
| **Trivial spoofing** | A MAC is asserted by the client in plaintext; `ip link set … address` rewrites it. MAC ACLs (`deny.mac`) are a speed-bump, not a control. |
| **OUI ≠ device** | OUI gives a *vendor guess* at best (and only for universal MACs). "Espressif" could be a sensor or a rogue dev board. |
| **Fingerprinting is thin** | Passive MAC/OUI fingerprinting "rarely captures who has what" (operator) — it can't see past L2. |

**Conclusion:** MAC binding is retained **only** for stable-OUI IoT (cameras, bulbs that don't randomize), and even then it is flagged as low-assurance. It is never the primary identity for a general client.

---

## 2. The layered identity model (defense in depth)

Assign a segment by the **strongest available** signal, falling through:

```
1. 802.1X / EAP  (cryptographic)   ── managed clients, the gold standard
2. Behavioural fingerprint         ── DHCP/mDNS/TLS profiling, survives MAC rotation
3. MAC + OUI (stable only)         ── IoT that can't do 802.1X, low assurance, flagged
4. Onboarding / captive segment    ── the unknown: low-trust, NOT punished
        … and over all of them …
5. Continuous trust (posture)      ── re-evaluate; anomaly → dynamic re-segment
```

### Layer 1 — 802.1X / EAP → VLAN via RADIUS  *(the durable path)*  ✅ built
Identity is a **credential** (EAP-TLS client cert, or PEAP/EAP-TTLS user creds), verified by RADIUS, which returns `Tunnel-Private-Group-Id = <vlan>`. **Survives MAC randomization** because the MAC is irrelevant to the decision. `via: dot1x` generates the RADIUS side (`fabric/62-<br>.radius`), and the **edge port** is now generated too: `wifi_cfg` renders a WPA2-Enterprise AP (`auth: eap` → `ieee8021x=1`, `wpa_key_mgmt=WPA-EAP`, `auth_server_addr/secret`, `dynamic_vlan=1` + `vlan_file`). The AP authenticates the client → RADIUS returns the VLAN → hostapd dynamic-VLAN assigns it. **L1 loop closed end-to-end** (hostapd-EAP ↔ RADIUS ↔ dynamic VLAN).

### Layer 2 — Behavioural fingerprint  *(MAC-independent identity)*  ✅ built (`crate::fingerprint`)
When 802.1X isn't possible, identify the device by **what it does**, not what MAC it claims:
- **DHCP fingerprint** — option 55 (parameter-request list) + option 60 (vendor class) + hostname → a stable device-type signature (Fingerbank-style).
- **mDNS / Bonjour / SSDP / UPnP** — service advertisements name the device.
- **TLS JA3/JA4**, HTTP User-Agent, and traffic behaviour (NetFlow shape).
This is **Senzorium/HYDRA** territory: the evidence graph ingests flows and host telemetry. The fingerprint → device-class → suggested segment becomes an **AEGIS** recommendation.

`crate::fingerprint::classify()` does exactly this, layered strongest-first (**mDNS model string > mDNS service > DHCP vendor-class > hostname > DHCP opt-55 > OUI**), and flags randomized MACs so they're never used as durable identity. `hookprobe-supervisor --classify <obs.json>` runs it; `--auto-segment <leases> --mdns <avahi> --dhcp-log <dnsmasq>` runs it on the **enriched live feed** (parsers: `parse_avahi_browse`, `parse_dnsmasq_dhcp_log`, merged by `enrich()`).

> **Enrichment proof (live N100, before → after):** with leases only, `E1680422` was `unknown` and `hooksound` mis-guessed `sbc`. Adding mDNS + the DHCP log: `E1680422` → **computer** (DHCP `vendor class: MSFT 5.0` = Windows), `hooksound` → **voice-assistant** (mDNS `md=HomePod` / `model=AudioAccessory5,1`) — which also corrects its segment infra→iot. **0 unknowns, all correct.** This is exactly why segmentation needs richer signals than MAC/OUI.

> **Live proof (N100 LAN, real `dnsmasq.leases`):** 5 devices, **2 with randomized MACs** — the iPhone (`c2:…`) and the Mac (`9e:…`) — both correctly classified `phone`/`computer` → `byod` purely from hostname, despite having no OUI. The Pi (`dc:a6:32`) → `sbc` via OUI+hostname. An unrecognised device → **`unknown` → onboarding** (honest, not misclassified). This is precisely the "who has what" that MAC/OUI filtering misses.

Remaining: ingest the signals *automatically* (Senzorium → DHCP opt-55/mDNS/TLS into the observation feed) and turn `suggested_segment` into an AEGIS plan-as-diff. DHCP opt-55 and TLS JA3/JA4 inputs are wired in the schema; the live feed is next.

### Layer 3 — MAC + OUI  *(retained, demoted, honest)*
Only for **universally-administered** MACs (stable OUI). `crate::fabric::mac_class()` detects the locally-administered bit; a randomized MAC binding is rendered with an `# UNSTABLE` banner and a `via: dot1x` recommendation rather than pretending it's identity. Good for the camera on VLAN 30; never for the phone.

### Layer 4 — Onboarding segment  *(the unknown, handled well)*
Un-bound / randomized / un-authenticated devices land in a **low-trust onboarding VLAN** (intent `unknown_segment`), not a silent `drop` and not a punitive "quarantine". A catch-all `priority=10,actions=mod_vlan_vid:<onboarding>` flow. From there: captive portal, limited egress, observe-and-classify, then promote. (Quarantine remains a *separate*, deliberate fail-closed segment for known-bad.)

### Layer 5 — Continuous trust  *(identity is not one-time)*  ✅ built (`crate::trust`)
Segment membership is re-evaluated continuously: a device that authenticated cleanly but later trips the **QSECBIT** risk score or a **HYDRA** threat verdict is **dynamically re-segmented** (moved to the quarantine VLAN), via the same generated-flow path. `trust::evaluate()` maps a `PostureSignal {risk, threat}` to `keep` / `step-up` (re-auth, stay) / `quarantine`; `render_quarantine_flows()` emits a **priority-250 override** `dl_src→quarantine-VLAN` flow that sits *above* the device's normal binding (200), so quarantine wins immediately and **reverts cleanly when the posture clears** (the override is removed). `--trust-eval <posture.json>`. This ties segmentation to the detection plane instead of freezing trust at join time.

---

## 3. Enforcement is layered too (not just VLANs)

VLAN/segment is the **coarse** boundary. Real isolation needs east-west controls:

| Scope | Mechanism | Status |
|---|---|---|
| Port admission | 802.1X (hostapd/wpa_supplicant + RADIUS) | `via:dot1x` → RADIUS artifact ✅; hostapd-EAP mode ⬜ |
| North-south segment | VLAN (OVS internal port / Linux-bridge vlan_filtering) | ✅ `crate::fabric` |
| Segment↔segment | OpenFlow inter-VLAN allow/deny; cloud nftables cross-VRF drop | ✅ (flows + VRF nft) |
| **East-west (intra-segment)** | **microsegmentation** — OVS conntrack stateful rules / nftables `ct state` (`crate::microseg`) | ✅ built |
| Posture-driven | dynamic quarantine on QSECBIT/HYDRA signal (`crate::trust`) | ✅ built |

Microsegmentation matters because devices *in the same VLAN* should still not freely talk (a compromised camera shouldn't reach another camera). OVS `conntrack` actions and eBPF give per-flow zero-trust inside a segment — beyond what VLANs alone express.

---

## 4. Mapping to HookProbe components

```
Senzorium  ── observe: DHCP/mDNS/TLS/flows → device fingerprint
HYDRA      ── enrich: fingerprint → device class, threat signals
QSECBIT    ── score: per-device/per-segment risk
AEGIS      ── decide: identity+fingerprint+posture → segment (intent, as a plan/diff)
fabric     ── generate: 802.1X/RADIUS + VLAN + OpenFlow + (next) microseg + cross-VRF
NAPSE      ── the out-of-band mirror tap feeding detection
```
Segmentation is therefore not a standalone feature — it's the evidence graph + AEGIS choosing a segment, the `fabric` reconciler rendering it as a signed-manifest-derived artifact, and the detection plane continuously re-deciding.

---

## 5. Built vs. next

**Built (`crate::fabric` + `crate::fingerprint`, 58 lib tests):**
- **Behavioural fingerprint** (`crate::fingerprint`) — MAC-independent device→class→segment, layered (mDNS > vendor-class > hostname > opt-55 > OUI), randomized-MAC aware. Validated on the live N100 LAN (randomized iPhone/Mac classified correctly). `--classify` CLI.
- MAC-class detection (`mac_class`) — randomized (locally-administered) MACs flagged `# UNSTABLE`, never trusted as identity.
- 802.1X `via: dot1x` → RADIUS `Tunnel-Private-Group-Id` artifact (durable identity path).
- Onboarding `unknown_segment` catch-all (no silent quarantine/drop).
- VLAN segments (OVS internal ports / Linux-bridge vlan_filtering), per-segment fail-open/closed, inter-segment baseline flows, out-of-band mirror taps; L3 VRF routing separation for the cloud; capability-gated OVS↔Linux-bridge fallback; topology-driven auto/hybrid plane selection.

**Also built — the AEGIS bridge (identity → segment → enforcement, as a plan-as-diff):**
- `fingerprint::recommend()` decides segment **and enforcement mechanism**: stable-MAC identified device → `mac-flow`; **randomized-MAC identified device → `dot1x`** (never a churning `dl_src` flow); unidentified → `observe`/onboarding. `--auto-segment <leases>` runs the live loop and emits a ready `fabric` `mac_bindings` fragment.
- **Validated end-to-end on the live N100:** leases → identity → AEGIS → fabric — the Pi → OpenFlow flow (VLAN 40), the randomized iPhone/Mac → RADIUS `Tunnel-Private-Group-Id` (VLAN 60, via 802.1X), the unknown → onboarding (VLAN 99). hostapd-EAP supplies the matching AP port config. **62 lib tests.**

**Next (roadmap, in priority order):**
1. **Live signal enrichment** ✅ *mostly done* — mDNS (`avahi-browse`) + DHCP opt-60 vendor class (`log-dhcp`) + DHCP opt-55 signatures + mDNS model strings are parsed and merged into the feed (`--mdns`/`--dhcp-log`). Validated live (0 unknowns on the N100). *Remaining:* TLS JA3/JA4 ingestion (needs traffic capture via NAPSE) and wiring Senzorium to refresh the feed continuously rather than on-demand.
2. **Microsegmentation** ✅ *built* (`crate::microseg`) — per-segment east-west posture (`open` / `client-isolation` / `allowlist`) as stateful OVS conntrack flows + an nftables variant; established + gateway always pass, new lateral flows dropped in isolated segments, named exceptions (e.g. NVR→cameras RTSP) permitted above the drop. **Identity-driven defaults:** `default_isolation_for_segment` auto-isolates cameras/iot/onboarding/guest while keeping byod/infra open, so segments derived from fingerprinting get sensible posture with no hand-written policy. *Remaining:* eBPF/XDP per-flow as a third backend.
3. **Continuous trust** ✅ *built* (`crate::trust`) — posture (QSECBIT risk + HYDRA threat) → keep/step-up/quarantine, rendered as a reverting priority-250 override flow. **Live feed + autonomous loop:** `build_posture` reads the detection plane's own files (`arp-status.json` presence + `blocked_macs.json` threat, **including V1's MD5-hashed MAC entries** via `crate::md5`), and `reconcile()` converges each cycle — adds overrides for newly-quarantined devices and **`del-flows` for recovered ones (auto-revert)**. A `--quarantine-state` file makes the cycle self-contained, run by **`hookprobe-trust-reconcile.timer` every 30 s** (`base/units` + `base/scripts/trust-reconcile.sh`). *Remaining:* wire QSECBIT's numeric score (today threat is binary from `blocked_macs`).
4. **Group-based policy** — identity → security-group → policy, decoupled from VLAN/IP, so policy scales without per-MAC/per-VLAN sprawl.
