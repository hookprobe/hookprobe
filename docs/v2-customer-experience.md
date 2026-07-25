# HookProbe OS V2 — Simplified Customer Experience

> **This sits *on top of* `docs/MissionControl.md`. It does not replace it.**
> Mission Control stays the full capability **superset** (13 workspaces · ~110 routes · the dense "pro" surface in `~/hookprobe-v2-dashboard.png`). This document specifies the **legible customer skin** over that superset: the handful of surfaces a real customer wants, in plain language, in the fewest steps — with all of V1's power kept *under the hood* and revealed only on demand.
>
> **The V1 lesson (the whole reason this doc exists):** V1 Fortress had the power but failed on **legibility** — customers couldn't tell what they were buying or seeing (a 14-item AdminLTE sidebar of `bubbles / sdn / clients / networks / dnsxai / aiochi / slaai / aegis / mssp / vpn / tunnel / security / settings …`, exposing engine names — `HYDRA`, `AIOCHI`, `QSecBit`, `OVS`, `OpenFlow`, `DBSCAN` — to people who just wanted to know "is my network safe and is my Apple TV working?"). V2's job is to **present only what the customer wants** and generate the V1 complexity *for* them.

**Status:** additive design spec. Companion to `docs/v2-reconciliation.md` (decision **D1**: the gateway/router role is first-class) and `docs/V2-investigation.md` (customer-first / fewest-steps mandate). Where this and MissionControl.md differ, MissionControl.md wins on capability; this doc wins on *what is shown by default*.

---

## 0. The five customer pillars (the entire surface, named)

Everything a customer touches by default collapses to **five legible surfaces**. Each is a friendly lens; each is backed by a proven V1 engine that the customer never has to name.

| # | Customer pillar (their words) | Default surface | V1 engine under the hood | MissionControl home |
|---|---|---|---|---|
| **1** | **"Block the ads and junk"** — DNS / ad-blocker | **Shield** card + DNS surface | `dnsXai` DoH resolver (live on Guardian) | Detect/Protect → DNS |
| **2** | **"See and run my network"** — LAN management | **My Network** (device map + Bubbles) | Bubbles, `device_policies`, `sdn_autopilot` (OVS/OpenFlow), Fingerbank NAC, mDNS clustering | **Network/Gateway** (new, D1) + Protect |
| **3** | **"Get me online / fix my Wi-Fi"** — router setup | **Get Online** wizard | PPPoE/DHCP/LTE WAN, PBR failover, hostapd, DFS | **Network/Gateway** (new, D1) |
| **4** | **"Am I safe, what happened, is it handled?"** — a SOC they can *understand and control* | **Organism orb** + incident stories | Senzorium / NAPSE / AEGIS / QSecBit / Automate | Mission Control · Observe · Detect · Investigate · Protect · Automate |
| **5** | **"It's my data — let me see it and take it"** — traceability + export/API | **Timeline & Export** | Evidence graph · Telemetry Fabric · `aegis-ledger` | Observe · Administration → Integrations/API |

**Design contract for all five:** *one simple customer surface · one V1 engine doing the work · zero engine jargon on the default path.* The jargon (HYDRA / CNO / AIOCHI / OVS / OpenFlow / DBSCAN / Viterbi-HMM) lives in progressive-disclosure depth (§5), reachable, never mandatory.

---

## 1. Personas and their jobs

Four personas, gated by **mode** (standalone / cloud-linked) and **manifest** (what the box can do). Most home/prosumer boxes are standalone; SMB and MSSP are cloud-linked. The same app, fewer or more lenses.

### 1.1 Home / Prosumer ("Sam") — *standalone, the legibility make-or-break*
The person V1 lost. Not a security engineer; owns ~25 devices, an Apple household, kids, IoT. Wants a calm answer and big obvious controls.

| Job (their words) | Pillar | Default surface | Fewest-steps target |
|---|---|---|---|
| "Get me online" (new box) | 3 | Get Online wizard | first boot → online ≤ 4 steps |
| "Is my network safe right now?" | 4 | Organism orb (lands here) | 0 clicks (it's the landing) |
| "Block ads/trackers on everything" | 1 | Shield card (on by default) | 0 clicks; tune ≤ 1 |
| "Show me my devices" | 2 | My Network device map | 1 click |
| "Put the kids' tablets in their own zone" | 2 | Bubbles, drag or ask | ≤ 2 (or 1 via Copilot) |
| "Let the living-room stuff see the Apple TV" | 2 | Bubble + Apple ecosystem toggle | ≤ 2 |
| "Stop this camera talking to anything but the internet" | 2 | Device → one toggle | 1 |
| "What was that alert? am I ok?" | 4 | Incident story | 1 click, plain English |
| "Trust this new phone / block that one" | 2 | Device → Trust / Block | 1 |

### 1.2 SMB owner / IT generalist ("Dana") — *standalone or cloud-linked*
Runs a shop/clinic; no SOC team; the bar to beat is **Blumira** (≈15–30 min/week to operate). Wants compliance-able security without a query language, plus the same LAN/Wi-Fi control as Sam at slightly larger scale (POS VLAN, staff vs guest Wi-Fi).

Adds to Sam's jobs: *segment POS from guest Wi-Fi* (Bubbles → Corporate/Guest types), *prove it's handled* (Investigate → Executive Summary), *get a report for the auditor* (Pillar 5 export), *approve or auto-run responses* (Pillar 4, Automate autonomy per playbook).

### 1.3 MSSP analyst ("Priya") — *cloud-linked, the dense pro surface*
Lives in the full `~/hookprobe-v2-dashboard.png`. Multi-tenant; swivels between customers via the scope switcher. Wants triage speed, plan-as-diff control, cross-fleet IOC sweeps. **This persona sees the superset by default** — for Priya, the "simplified" skin is a per-customer *lens*, not her own workspace. Her jobs are MissionControl.md's Investigate/Detect/Customers/Intelligence as-is.

### 1.4 Admin / installer ("Alex") — *any mode*
Provisions, enrolls, sets WAN/Wi-Fi, defines who-can-do-what, wires export/API. Touches the Get Online wizard (Pillar 3) and Administration. After day-1, hands the calm surface to Sam/Dana.

**What this means for the default build:** Sam and Dana get the **five-pillar skin**. Priya and Alex can flip to the **full superset** (a single "Pro view" toggle, §5.3). Standalone never shows fleet/tenant/business; cloud-linked adds the scope switcher exactly as MissionControl.md specifies.

---

## 2. The minimal default experience + first-run

### 2.1 First boot — "Get Online" (Pillar 3), zero config files
Time-to-SOC ≈ first boot is the north star (`V2-investigation.md`). The SOC is **already running** the instant the box boots (bootstrap wrote the manifest once). The *only* thing a customer must do is connect the uplink — and even that is a 4-card wizard, never a config file.

```
┌────────────────────────────────────────────────────────────────┐
│  Welcome to HookProbe                              ●●●○  Step 3/4 │
│                                                                  │
│   How do you connect to the internet?                            │
│                                                                  │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│   │  ◉ Cable /   │  │  ○ DSL /     │  │  ○ Mobile /  │          │
│   │    Router     │  │    Fibre      │  │    LTE 4G/5G │          │
│   │  (automatic)  │  │  (PPPoE login)│  │  (SIM)       │          │
│   └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│   ☑ Use my mobile as automatic backup if the line drops          │
│                                                                  │
│   Detected: WAN cable on Port 1 · link up · IP via DHCP ✓        │
│                                                          [Next →] │
└────────────────────────────────────────────────────────────────┘
```

The wizard, in four steps: **(1)** name your network + set Wi-Fi name/password → **(2)** pick a Region/admin password → **(3)** uplink (above) → **(4)** "Protect everything?" (Shield/DNS on, sensible bubbles seeded). Then **Done → lands on the Organism orb.** No VLAN numbers, no PBR tables, no `hostapd.conf`.

> **What V1 complexity this generates under the hood** (the customer sees none of it): hostapd AP config + DFS channel pick, dnsmasq DHCP/DHCPv6-PD scopes, PPPoE/LTE interfaces, the **PBR failover tables 100/200/300** + nftables fwmarks, the OVS `FTS` bridge, and dnsXai as the DoH resolver. All emitted by AEGIS from the four answers, applied by the deterministic reconciler, verified, and shown back as one line: *"You're online and protected."*

### 2.2 The landing — the calm home (Pillars 1 + 4 + 2 at a glance)
Standalone customers land on a **single calm screen**, not the 13-workspace bento. The one bold element is the Organism orb (QSecBit + heartbeat); everything else is quiet and answers the four security questions plus the two everyday network questions.

```
┌───────────────────────────────────────────────────────────────────────────┐
│  HookProbe          ⌘K  Ask anything…                    [standalone] ● Sam │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│            ╭──────────────╮     YOU'RE PROTECTED                            │
│            │              │     Nothing needs you right now.                │
│            │   ◍  92      │     Last checked just now · heartbeat ▁▂▃▅▃▂▁    │
│            │   QSecBit    │                                                 │
│            ╰──────────────╯     [ What happened today ▸ ]                    │
│                                                                             │
│  ┌─ SHIELD (Pillar 1) ──────────┐  ┌─ MY NETWORK (Pillar 2) ─────────────┐  │
│  │ 🛡  4,812 ads & trackers      │  │  24 devices · 22 online             │  │
│  │     blocked today             │  │  Family 9 · IoT 7 · Guests 3 · …    │  │
│  │  12 malware sites stopped     │  │  ● all in a zone, 1 needs a name    │  │
│  │            [ Manage ▸ ]       │  │            [ Open map ▸ ]           │  │
│  └──────────────────────────────┘  └─────────────────────────────────────┘  │
│                                                                             │
│  ┌─ NEEDS YOU ──────────────────────────────────────────────────────────┐  │
│  │  (empty)  Nothing to approve. We isolated 1 risky device on our own.   │  │
│  │           [ See what we did & why ▸ ]                                  │  │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  More:  Get Online · Timeline & Export · Pro view ⤢                          │
└───────────────────────────────────────────────────────────────────────────┘
```

**Rules for the landing:**
- **Plain-language verdict first.** "You're protected / Something needs you" — the QSecBit number is *secondary* to the sentence. (V1 showed a `GREEN/AMBER/RED` RAG badge with no story; V2 leads with the story.)
- **Two everyday cards** (Shield, My Network) because those are the things a home customer touches weekly — they earned their place; the 11 other workspaces did not, by default.
- **"Needs you" is the only queue.** If empty, say so and show what the system handled autonomously — *with a link to why* (glass-box, not black-box). This is the V1 legibility fix made literal.
- **Everything drills.** Every number is a link into the evidence graph (MissionControl drill-down contract). No dead-end numbers.
- **`⌘K` Copilot is the front door for anything not on screen** — "show me last night", "block the camera", "is my Apple TV ok". Intent, not navigation.

### 2.3 Mode-aware variants
- **Standalone (default):** the screen above. No scope switcher, no fleet/tenant/business, no Customers card.
- **Cloud-linked (SMB/MSSP):** adds the scope switcher (this device / site / fleet / tenant) and — for Priya — a one-toggle jump to the full `~/hookprobe-v2-dashboard.png`. The calm skin becomes the *per-customer* lens.
- **Offline / degraded:** the orb keeps its last verdict with an honest banner — *"Offline — enforcing last approved state. Last checked 14:02."* Controls that need the cloud grey-with-reason; local protection (DNS, bubbles, isolation) keeps working because it's all on-box.

---

## 3. Pillar surfaces in detail

### 3.1 Pillar 1 — Shield (DNS / ad-blocker)
The feature customers *immediately get*. Backed by **dnsXai** (the V1 DoH resolver already running on Guardian). On by default from the wizard.

```
┌─ SHIELD ─────────────────────────────────────────────────────────────┐
│  Protecting 24 devices · on since setup                    ● Active   │
│                                                                       │
│   Today:  4,812 ads/trackers blocked   12 malware/phishing stopped    │
│           ▁▂▅▇▅▃▂▁▂▄▆▇▅▃  (last 24h)                                  │
│                                                                       │
│  Top blocked:  doubleclick.net 312 · graph.facebook 188 · …  [why?]   │
│                                                                       │
│  Allow list  (3) ─ "I trust these"        [+ Add]                     │
│  Block list  (custom 5)                   [+ Add]                     │
│                                                                       │
│  Per-device / per-zone:                                               │
│   Kids' zone   ▸  Strict (no adult content) + ads/malware             │
│   Guests       ▸  Ads/malware only                                    │
│   Everything   ▸  Ads/malware  (default)                              │
└───────────────────────────────────────────────────────────────────────┘
```

- **One toggle to be safe** (on by default); per-device/per-zone policy is a dropdown, not a config.
- **"why?"** opens the AI explanation panel (*why blocked · confidence · evidence · related events*) — same panel as everywhere.
- **Under the hood:** dnsXai DoH resolver + ML domain scoring; per-zone DNS policy is keyed to the **bubble VLAN** (Pillar 2), so "Kids' zone = Strict" is one switch that the reconciler turns into resolver rules. Customer never sees DoH, VLAN, or resolver config.
- **Capability-gate:** hidden if the manifest doesn't grant `dns_filtering`; greyed-with-reason if the resolver service is down.

### 3.2 Pillar 2 — My Network (LAN management: device map, Bubbles, device-to-device, Apple ecosystem, trust/tag)
The heart of the LAN surface and the biggest V1 simplification. **A "Bubble" = a named zone of devices that share a network policy** (internet/LAN/each-other/smart-home access). V1 already ships the engine: group types `Family / Guest / Corporate / Smart-Home / LAN-only / Quarantine / Custom`, family presets (Dad's/Mom's/Kids'/Guests/Work), drag-to-move, pin-to-lock, AI suggestions, custom device names, and an undeletable **Quarantine** jail. V2 keeps all of it; it just stops calling it `sdn` / `clients` / `OpenFlow`.

**The device map (the default Pillar-2 view):**

```
┌─ MY NETWORK ──────────────────────────────────────────  [Map] [List] ⌘K ┐
│                                                                          │
│         ╭─ Family ────────╮      ╭─ Smart Home ───────╮                  │
│         │ 📱 Sam's iPhone  │      │ 🔊 HomePod         │   ╭─ Guests ──╮  │
│         │ 💻 Sam's MacBook │┈┈┈┈┈┤ 📺 Living-room TV  │   │ 📱 ?-iPad │  │
│         │ ⌚ Sam's Watch   │      │ 💡 Hue bridge      │   │ (1 more)  │  │
│         ╰─────────────────╯      ╰────────────────────╯   ╰───────────╯  │
│              Apple ✦ linked          shared by family                    │
│                                                                          │
│         ╭─ Kids ──────────╮      ╭─ Quarantine 🔒 ────╮                   │
│         │ 📱 iPad mini     │      │ 📷 Unknown camera  │  ← we isolated   │
│         │ 🎮 Switch        │      │    (talks to China)│    this for you  │
│         ╰─────────────────╯      ╰────────────────────╯                  │
│                                                                          │
│  Drag a device to a zone, or:  ⌘K "put the new iPad in Kids"             │
│  [+ New zone]   1 device needs a name → [Name it]                        │
└──────────────────────────────────────────────────────────────────────────┘
```

Dotted lines = devices that are **allowed to talk to each other** (device-to-device). Solid grouping = the zone. The customer reads it like a family photo, not a flow table.

**Device drawer (tap any device) — trust/tag and per-device policy in one place:**

```
┌─ Sam's iPhone ────────────────────────────────────────────────┐
│  Apple iPhone 15 · online · Family zone · seen 2s ago          │
│  Identified by: name "Sam's iPhone" + Apple fingerprint (98%)  │
│                                                                │
│  Trust:   ◉ Trusted   ○ Normal   ○ Guest   ○ Blocked           │
│  Can reach:  ☑ Internet   ☑ Other home devices   ☑ Smart home  │
│  Zone:    Family ▾        Rename ✎        Pin to this zone 📌   │
│                                                                │
│  [ Block now ]   [ See its activity ▸ ]                        │
└────────────────────────────────────────────────────────────────┘
```

**Three intent-driven, drag-simple actions (the brief's examples) — and the V1 complexity each generates:**

| Customer action (1–2 clicks, or 1 Copilot sentence) | What V2 shows back | Generated under the hood (customer never sees) |
|---|---|---|
| **"Put the kids' tablets in their own bubble"** — drag 2 devices into a new "Kids" zone, or `⌘K` it | A plan-as-diff: *"New Kids zone · internet yes · home devices no · Strict DNS · 2 devices."* [Approve] | New bubble (`type=family`-derived, custom), VLAN assignment, `device_policies` per MAC, OVS OpenFlow table-10/20 isolation rules via `sdn_autopilot`, Kids DNS profile on dnsXai |
| **"Let the living-room devices see the Apple TV"** — toggle *Apple ecosystem* on the Living-room/Smart-Home zone | *"AirPlay, HomeKit and casting will work between these devices — still hidden from Guests."* | mDNS/Bonjour **reflection** scoped to the bubble (`_airplay`, `_raop`, `_hap/_homekit`, `_companion-link`, `_sleep-proxy`), `d2d_allowed=true` flows between those MACs only, cross-bubble drop kept |
| **"Stop this camera talking to anything but the internet"** — device drawer, untick *Other home devices* | *"Camera can reach the internet only. It can't see your other devices."* | `device_policies → INTERNET_ONLY`, OVS peer-isolation flows, mDNS not reflected for it |
| **"Block that device" / "Trash it"** — drag to Quarantine or Block now | *"Isolated. No internet, no LAN. Reversible."* | `NetworkPolicy.ISOLATED`, ebtables L2 drop, added to undeletable Quarantine bubble + blocked-MAC list |

**Apple-ecosystem bubbles, made legible.** V1's behavioral clustering (DBSCAN over mDNS services, time-correlation, proximity, sync-frequency, handoff count) already auto-detects "John's iPhone + Watch + iPad" as one person's cluster, and mDNS resolution turns `_companion-link._tcp` into the friendly "Sam's Watch". V2 surfaces this as a quiet **"Apple ✦ linked"** label and an **AI suggestion chip**, never as "DBSCAN ecosystem bubble":

```
💡  Sam's new AirPods keep pairing with Sam's iPhone.  Add to Family zone?   [Yes] [Not now]
```

The crucial Apple promise — **AirPlay/HomeKit/AirDrop works *inside* your zone while staying invisible to Guests/IoT** — is the single *Apple ecosystem* toggle above. That is the friendly name for "mDNS reflection within a bubble, isolated across bubbles."

- **Manual beats AI, always.** Dragging or pinning a device wins over the auto-clustering (V1 `is_pinned` / `manual_assignments`). The AI only *suggests*; the customer holds the wheel (the legibility/control principle).
- **Capability-gate:** the map is read-only (alert-only) if `openvswitch`/`sdn` isn't granted — it still *shows* zones and trust, but the enforcing toggles grey-with-reason ("this box can see but not segment"). Apple-ecosystem toggle hidden without mDNS support.

### 3.3 Pillar 3 — Get Online (router/Wi-Fi setup, beyond first-run)
The wizard (§2.1) is the first-run; the standing surface is a calm status + edit page — the customer's "router admin," minus the router-admin pain.

```
┌─ GET ONLINE ──────────────────────────────────────────────────────────┐
│  Internet:  ● Connected (Cable, Port 1)   Backup: ● Mobile ready        │
│             Down 487 Mbps · Up 51 Mbps · 12ms                           │
│                                                                         │
│  Wi-Fi:                                                                 │
│   "Sam-Home"      2.4+5GHz   ● 18 devices   [Edit] [QR to share]        │
│   "Sam-Guests"    5GHz       ● 3 devices    [Edit]  (auto-isolated)     │
│                  Best channel auto-picked (radar-safe) ✓                │
│                                                                         │
│  [ Run a speed test ]   [ Restart internet ]   Advanced (PPPoE/LTE/VLAN)▾│
└───────────────────────────────────────────────────────────────────────┘
```

- **Wi-Fi for guests creates a Guest bubble automatically** — one network, isolation handled (Pillar 2 link). No VLAN literacy required.
- **"Best channel auto-picked (radar-safe)"** is the friendly face of V1's DFS channel intelligence/ML scoring. The DFS score, radar-event history, and channel switches live behind **Advanced**.
- **Multi-WAN/failover** is one checkbox ("use mobile as backup") → generates PBR tables + fwmarks. The standing surface shows it as *"Backup: ● Mobile ready"*, and if it ever fails over, the customer gets one plain line: *"Your cable dropped at 14:02 — we switched to mobile. Back on cable now."*
- **Capability-gate:** `wan`/`multi_wan`/`wifi_ap`/`wifi_dfs` from the manifest. A cloud VM with no radios hides Wi-Fi entirely; an LTE-less box hides the backup checkbox.

### 3.4 Pillar 4 — Security you can understand AND control (SIEM/SOAR/SOC, legible)
The V1 legibility fix, fully realized: not a black box. The customer sees the **why** and **holds the wheel**. This maps to MissionControl.md's Observe/Detect/Investigate/Protect/Automate — but the *default* customer never sees five workspaces. They see: the **orb** (am I safe), the **"What happened today" story feed** (what happened), the **incident story** (the narrative + why), and **plan-as-diff approvals** (control).

**"What happened today" — the story feed (replaces a log console):**

```
┌─ WHAT HAPPENED TODAY ─────────────────────────────────────────────────┐
│  09:14  We isolated an unknown camera                       [handled]  │
│         It tried to reach a known-bad server. We cut it off.           │
│         Why we're sure ▸  ·  Undo ▸                                     │
│                                                                        │
│  02:31  Blocked 188 tracker requests from the smart TV      [handled]  │
│  Yesterday  A guest phone joined Guests zone                [info]      │
│                                                                        │
│                                          [ See full timeline ▸ ]       │
└────────────────────────────────────────────────────────────────────────┘
```

**Incident as a story (open any item) — the differentiator vs a SIEM query screen:**

```
┌─ Unknown camera isolated ───────────────────────────  Confidence 96% ──┐
│  STORY                              │  WHY WE DECIDED THIS              │
│  09:14:02  Camera came online       │  • Reached 185.x (known C2) ✓    │
│  09:14:08  Asked DNS for bad domain │  • Matches IoT-botnet pattern    │
│  09:14:09  We blocked the domain    │  • 3 similar cases this month    │
│  09:14:10  It tried a direct IP     │  Model: aegis-local · evidence:24│
│  09:14:11  We isolated the device   │  MITRE: T1071 Command & Control  │
│                                     │                                  │
│  WHAT WE DID (and can undo)         │  [ Keep isolated ] [ Undo ]      │
│   ✓ Isolated camera (auto)          │  [ Make a rule: always isolate   │
│   ○ Notify you            done      │    cameras like this ]           │
└────────────────────────────────────────────────────────────────────────┘
```

- **Plain-English everywhere; the query is evidence, not input.** "Show me logins from new countries this week" works in `⌘K`; the generated detection/query is shown *as evidence*, never required. (Beats Sentinel KQL barrier.)
- **Control = plan-as-diff + autonomy dials.** Any AEGIS action is a diff the customer can approve, undo, or promote to a rule. **Autonomy is tunable per playbook** in one simple control (the SOAR/Automate surface, kept plain):

```
┌─ HOW MUCH SHOULD WE HANDLE ON OUR OWN? ───────────────────────────────┐
│  Block bad websites/DNS        ● Automatic        ○ Ask me            │
│  Isolate an infected device    ● Automatic        ○ Ask me            │
│  Isolate a *server*            ○ Automatic        ● Ask me  ← default  │
│  Quarantine a person's phone   ○ Automatic        ● Ask me            │
│                                                   [ Save ]            │
└────────────────────────────────────────────────────────────────────────┘
```

- **Under the hood:** Senzorium capture → NAPSE detection (Viterbi-HMM + Bayesian + signatures, MITRE-mapped) → AEGIS narrative + plan → reconciler enforces. HYDRA threat-intel enriches; QSecBit rolls it into the orb. The customer sees a story and a switch — none of those names.
- **Capability-gate:** active controls (isolate/block/segment) need the relevant grants; without them the story feed is **alert-only** and the autonomy dials grey-with-reason ("this box can detect but not enforce — connect it inline to act").

### 3.5 Pillar 5 — Timeline & Export ("it's my data")
Trust is sold by transparency and portability — the inverse of Darktrace opacity and Sentinel lock-in. Two promises: **full traceability** (any number → its raw evidence) and **get my data out / call us programmatically**.

```
┌─ TIMELINE & EXPORT ───────────────────────────────────────────────────┐
│  Everything is traceable:  number → event → packet → raw  (try it ▸)   │
│  We keep ~ 21 days of detail on this box (312 GB).  [Extend ▸]          │
│                                                                        │
│  SEND MY DATA TO…           ⌘K "send alerts to my Splunk"              │
│   ☑ Syslog / CEF  → siem.acme:514            ● flowing                 │
│   ☐ Webhook       → (add URL)                                          │
│   ☐ S3 / object store (long-term)                                      │
│                                                                        │
│  USE THE API                                                           │
│   Token  hk_live_••••  [Copy] [Roll]      Docs ▸   (read events,       │
│                                            push actions, pull reports) │
└────────────────────────────────────────────────────────────────────────┘
```

- **Honest retention** (the real window + fill), with offload to exceed it — never the Sentinel per-GB surprise.
- **Export is a customer right, surfaced**, not buried in Administration: SIEM/syslog/CEF egress, webhooks, object store, and a clean read/write **API** with a self-serve token.
- **Under the hood:** the evidence graph (`Device→…→Threat→Incident→Response→Report`) + Telemetry Fabric pipeline + the signed `aegis-ledger`. Drill-down is the same universal contract from MissionControl.md.
- **Capability-gate / mode:** export targets that need the cloud grey-with-reason when offline; API token scope follows RBAC.

---

## 4. Fewest-clicks maps (before → after)

Click/decision counts for the top jobs, customer-first skin vs. a typical incumbent. Counts are *decisions to result*, cold start.

### Security jobs (vs Microsoft Sentinel / Defender XDR)

| Job | Incumbent path | Steps | HookProbe V2 | Steps |
|---|---|---|---|---|
| **"Is my network safe right now?"** | Sentinel: log in → workspace → workbook → load → read tiles | 4–5 | Land on orb — verdict in a sentence | **0** |
| **"SOC live at all"** (deploy) | Sentinel: connect data, 90–120 min; Defender: ~10.9 consoles | hours | First boot — already running; uplink wizard | **≤4 (once)** |
| **"What happened last night?"** | Sentinel: write/find KQL → run → pivot | 3–6 + syntax | `⌘K` "show me last night" → story feed | **1** |
| **"Isolate that host"** | Defender XDR: find device → action menu → isolate → confirm | 4 | Device drawer → Block now (or `⌘K`) | **1–2** |
| **"Why did it do that?"** | Darktrace: limited transparency, dig | many | "Why we decided this" panel on the incident | **1** |
| **"Tune how much it auto-acts"** | Multi-step playbook editor / KQL analytics rules | 5–8 | One autonomy panel, per-action switch | **1** |
| **"Get my data into my SIEM"** | Connector config, schema, billing tier | several | Timeline & Export → toggle Syslog/CEF | **2** |

### LAN / router jobs (vs a typical router/AP admin UI — e.g. UniFi/OpenWrt/consumer router)

| Job | Router-admin path | Steps | HookProbe V2 | Steps |
|---|---|---|---|---|
| **"Get online"** (new box) | WAN type → PPPoE creds → Wi-Fi SSID/PSK → channel → DHCP scope → save/reboot | 6–10 | 4-card wizard | **4** |
| **"Kids' tablets in their own zone"** | Create VLAN → subnet/DHCP → SSID or port map → firewall inter-VLAN rules → apply | 6–9 | Drag 2 devices to new zone → approve | **2** |
| **"Apple TV visible to living room, hidden from guests"** | Configure mDNS reflector/Avahi across VLANs → firewall exceptions → test | 5–8 (often unsupported) | Toggle *Apple ecosystem* on the zone | **1** |
| **"Camera: internet only, no LAN"** | Client isolation rule / ACL per VLAN | 3–5 | Device drawer → untick *Other home devices* | **1** |
| **"Block / trust a device"** | Find MAC → ACL/MAC filter → save | 3–4 | Device drawer → Block / Trusted | **1** |
| **"Guest Wi-Fi"** | New SSID → VLAN → isolation → schedule | 4–6 | "Sam-Guests" in Get Online (auto-isolated) | **1–2** |

The pattern: V1/incumbents make the customer *assemble* VLANs + DHCP + firewall + mDNS reflection by hand; V2 takes **one intent** and the reconciler assembles them.

---

## 5. Progressive disclosure, capability-gating, role-tailoring

The five-pillar skin is the **floor**, not a ceiling. The full MissionControl.md superset is always *reachable*, never *mandatory*. Three independent dials decide what a given customer sees.

### 5.1 By capability (the manifest) — *render, grey-with-reason, or hide*
Identical rule to MissionControl.md, applied to the skin:
- No `dns_filtering` → **Shield** hidden.
- No `openvswitch`/`sdn` → **My Network** shows zones/trust read-only; enforcing toggles grey-with-reason.
- No radios → **Get Online** hides Wi-Fi; no `multi_wan` → hides the backup checkbox.
- No inline grant → **Pillar 4** is alert-only; autonomy dials grey-with-reason.
- Offline → cloud-dependent export/scope grey-with-reason; local protection unaffected.

New capability tokens this skin implies (fold into `platforms/*.yaml` + ADR 0003, per `v2-reconciliation.md` §3): `wan`, `multi_wan`, `dhcp`, `dns`, `dns_filtering`, `wifi_ap`, `wifi_dfs`, plus the LAN-management trio **`segmentation`** (bubbles/zones), **`device_trust`** (NAC tag/trust/block), **`mdns_reflection`** (Apple-ecosystem D2D).

### 5.2 By persona / depth — *the same node, more lenses*
Disclosure is **layered, never a different app** (one evidence graph, MissionControl.md §1):
- **Layer 0 (default):** the five pillars. What Sam/Dana see.
- **Layer 1 (one click deeper):** any pillar's "Manage/Advanced" opens the relevant MissionControl workspace *scoped to that thing* — Shield → Detect/Protect DNS; My Network → Network/Gateway + Protect; a story → Investigate; Export → Administration → Integrations. Still plain-language headers; engine names appear only as small "powered by" footnotes.
- **Layer 2 (Pro view):** the full `~/hookprobe-v2-dashboard.png` — all 13 workspaces, rule builders, Sigma/YARA, OVS flow tables, DFS scores, PBR tables, threat graph. Where Priya lives.

**Jargon containment:** `HYDRA / CNO / AIOCHI / OVS / OpenFlow / DBSCAN / Viterbi-HMM / PBR / DoH / VXLAN` **never appear on Layer 0**. They surface only at Layer 2 or in an explanation panel's "details" expander. The default customer can operate the box for years and never read the word "OpenFlow."

### 5.3 The "Pro view" toggle
A single persistent control (`More: … Pro view ⤢`, and a permanent setting). Standalone home boxes default to **Layer 0**; cloud-linked MSSP defaults to **Layer 2**; SMB defaults to **Layer 0** with one-click promotion. RBAC can pin a role to a layer (e.g. a junior account can't leave Layer 0). The toggle changes *density and vocabulary*, never the data — same nodes, more lenses.

---

## 6. Mapping to the superset (additive, not a rewrite)

This skin **adds** one workspace and a set of capability tokens to MissionControl.md, and **re-presents** existing workspaces as customer pillars. Nothing in MissionControl.md is removed.

### 6.1 Pillar → MissionControl workspace/route
| Pillar | Default surface | MissionControl home (Layer 1/2) | Route(s) |
|---|---|---|---|
| 1 · Shield (DNS/ad-block) | Shield card | Detect (DNS detection) + Protect (DNS policy) | `/detect/*`, `/protect/network`, **new** `/network/dns` |
| 2 · My Network (LAN) | Device map + Bubbles | **Network/Gateway (new)** + Protect (segmentation/isolation) | **new** `/network/{map,zones,devices,trust}`, `/protect/{network,isolation,quarantine,zero-trust}` |
| 3 · Get Online (router/Wi-Fi) | Wizard + status | **Network/Gateway (new)** + Administration → Settings (networking) | **new** `/network/{wan,wifi,failover}`, `/admin/settings` |
| 4 · Security understood+controlled | Orb + stories + autonomy | Mission Control · Observe · Detect · Investigate · Protect · Automate | `/mission`, `/observe/*`, `/detect/*`, `/investigate/*`, `/protect/*`, `/automate/{playbooks,approvals,analytics}` |
| 5 · Timeline & Export | Timeline & Export | Observe + Administration → Telemetry Fabric / Integrations / API | `/observe/{events,live}`, `/admin/{telemetry-fabric,settings}` |

### 6.2 The new **Network / Gateway** workspace (D1) — proposed shape for MissionControl.md
`v2-reconciliation.md` D1 establishes the gateway/router as first-class and flags this workspace as a `ux-architect` task. Proposed shape (slots between **Protect** and **Automate** in the nav; capability-gated on `wan`/`dhcp`/`dns`/`wifi_ap`):

```
Network / Gateway              the router/LAN half (D1)
├─ Get Online        WAN: PPPoE · DHCP · LTE · multi-WAN failover (PBR), link health, speed
├─ Wi-Fi             APs (hostapd), SSIDs, bands, DFS/channel intelligence, guest Wi-Fi
├─ Device Map        all clients, online/idle/offline (ARP), drill to device
├─ Zones (Bubbles)   segmentation groups, types, drag-move, pin, AI suggestions, Quarantine
├─ Device Trust      NAC: identify (Fingerbank: DHCP+OUI+hostname+mDNS), tag, trust, block
├─ Apple/IoT Ecosystem  mDNS reflection scope per zone (AirPlay/HomeKit/cast), D2D matrix
├─ DNS / Shield      dnsXai resolver, ad/tracker/malware blocking, per-zone DNS profiles
└─ Segmentation Flows (Pro)  the generated OVS/OpenFlow + VLAN + nftables artifacts (read/edit)
```

- **Run-phase placement.** In MissionControl.md's lifecycle table, Network/Gateway is a **Run** workspace (operate the live gateway), with build-time bits (image radios, platform NIC mapping) staying in Administration.
- **Mode/visibility.** Standalone & cloud-linked: ✓ (this device / scope). The customer pillars (Get Online, Device Map, Zones, Shield) are Layer 0; **Segmentation Flows** is Layer 2 (Pro) — the explicit home for OVS/OpenFlow/VLAN/PBR artifacts, so they exist but never leak onto the default path.
- **Reconciliation note for MissionControl.md:** add Network/Gateway to the Navigation map, the route map appendix (`/network/{...}`), and the visibility-by-mode table; add the capability tokens from §5.1. This is the only structural addition; the §7/§8 Automate/Intelligence bodies still need the HYDRA-revert fix already tracked in `v2-reconciliation.md` §5.

### 6.3 What was simplified / merged / hidden — and the trade-off
| Simplification | What it merges/hides | Trade-off (and why it's safe) |
|---|---|---|
| 13 workspaces → **5 pillars** by default | Workspace, Knowledge, Business, Customers, Intelligence, raw Detect/Automate hidden at Layer 0 | None lost — all reachable at Layer 1/2 and via `⌘K`. Trade-off: power users must toggle Pro view (one click; default for MSSP). |
| V1 sidebar (`bubbles/sdn/clients/networks/dnsxai/aiochi/slaai/aegis/mssp/vpn/tunnel/security/settings`) → **My Network + Shield + Get Online** | `clients`+`sdn`+`networks`+`bubbles` collapse into "My Network"; `dnsxai` → Shield; engine pages vanish from default | Same data, one node each. Trade-off: a few V1 power screens (raw flow tables, DFS scores) move to Layer 2 — accepted, since <1% of customers used them and they confused the rest. |
| VLAN/PBR/OpenFlow/mDNS-reflection config → **intent + plan-as-diff** | All hand-assembly of segmentation hidden | The artifacts are still generated, signed, and inspectable in Segmentation Flows (Pro). Trade-off: advanced users can't hand-edit on the default path — they flip to Pro. |
| Engine names (HYDRA/CNO/AIOCHI/QSecBit/DBSCAN) → **plain labels** | Jargon removed from Layer 0 | QSecBit keeps its name *only* on the orb (it's the one branded number, per MissionControl design language). Everything else gets a "powered by" footnote at Layer 2. |
| Log console → **"What happened today" story feed** | Raw event grid hidden by default | Full Observe/Telemetry still at Layer 1 + Export. Trade-off: none for the home/SMB customer — the story is strictly more legible. |

---

## 7. Accessibility, i18n, reduced-motion

- **Reduced-motion:** the orb's heartbeat, threat pulse, and mesh-link animation must honor `prefers-reduced-motion` — degrade to a static ring + numeric delta (MissionControl "respect reduced-motion"). The verdict sentence carries the meaning, so motion is never load-bearing.
- **Color is never the only signal.** green/amber/red always pair with a word ("Protected" / "Needs you" / "Critical") and an icon — the V1 RAG badge was color-only; V2 must not repeat that. Helps color-blind users and screen readers.
- **Plain-language first** is itself an accessibility and i18n win: short, literal sentences translate cleanly and read well on screen readers. Avoid idiom in the verdict strings.
- **i18n:** device/zone names are user data (already free-text in V1 `device_names`); pillar labels, verdict strings, and explanation templates must be externalized for translation. Numbers/units localized. RTL: the bento/map layouts must mirror.
- **Keyboard / `⌘K`:** the command bar is the accessibility fast-path — every primary job reachable by typing, no drag required (drag is an *alternative*, not the only way to move a device).
- **Density target the stack must hit (UX performance budget):** the calm Layer-0 surface and the dense Layer-2 must both deliver **sub-second interactions on edge hardware (Pi 5 / RK3588 / N100)** with live SSE updates — per ADR 0001 (SolidJS + SSE/HTTP-2 + Rust/Axum). The orb, Shield counters, and device map update live without full re-render; the device map must stay smooth at ~250 nodes on a Pi.

---

## Summary

**Personas & their job-surfaces.** Four personas, gated by mode + manifest. **Sam (home, standalone)** and **Dana (SMB)** get the five-pillar calm skin; **Priya (MSSP)** gets the full `~/hookprobe-v2-dashboard.png` superset as her default; **Alex (admin)** runs setup then hands over the calm surface. Every persona's jobs collapse to five legible pillars: **Shield (DNS/ad-block) · My Network (LAN) · Get Online (router/Wi-Fi) · Security-you-understand-and-control (SOC) · Timeline & Export**.

**Bubbles / Apple-ecosystem / device-to-device, presented simply.** A "Bubble" becomes a **named zone** on a family-photo **device map**. Drag a device into a zone, toggle *Apple ecosystem* on a zone, or untick *Other home devices* on a camera — each is 1–2 clicks (or one `⌘K` sentence) and returns a plain plan-as-diff. Under the hood those generate the exact V1 artifacts (OVS/OpenFlow isolation, VLANs, `device_policies`, mDNS reflection scoped per bubble, ebtables blocks, Fingerbank NAC) — the customer never sees VLAN, OpenFlow, or DBSCAN. Apple clustering surfaces as a quiet "Apple ✦ linked" label and a suggestion chip; manual/pin always beats the AI.

**Progressive-disclosure model.** Three independent dials: **capability** (manifest renders / greys-with-reason / hides), **depth** (Layer 0 five pillars → Layer 1 scoped workspace → Layer 2 full Pro view), and **persona/RBAC** (default layer per mode). Jargon is contained to Layer 2; the same evidence-graph node is shown through more lenses, never re-modeled.

**New Network/Gateway workspace (D1).** One additive workspace between Protect and Automate — `Get Online · Wi-Fi · Device Map · Zones(Bubbles) · Device Trust · Apple/IoT Ecosystem · DNS/Shield · Segmentation Flows(Pro)` — plus capability tokens `wan/multi_wan/dhcp/dns/dns_filtering/wifi_ap/wifi_dfs/segmentation/device_trust/mdns_reflection`. This is **additive to MissionControl.md** (nav + route map + visibility table + tokens), not a rewrite; the HYDRA-revert body fix already tracked in `v2-reconciliation.md` §5 still stands.

**Files:** spec written to `/home/andrei/hookprobe-os/docs/v2-customer-experience.md`.
