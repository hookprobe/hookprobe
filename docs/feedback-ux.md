# HookProbe OS — Customer-Feedback UX (the product-health beacon)

> **Canon:** `docs/MissionControl.md` (the target dashboard) and `docs/adr/0012-release-definition-cortex-pass.md` **D5** (operator decision, 2026-07-03: the customer-feedback return path is an opt-in, **off-by-default** product-health beacon with its own consent screen in Administration). This document specifies the UX for that decision only. Where this and MissionControl.md differ on capability, MissionControl.md wins; this doc owns *what the consent surface shows and how it behaves*.

**Route:** `/admin/feedback` — Administration → **Feedback & Diagnostics** (MissionControl.md §12, route-map appendix).
**Capability token:** `feedback_beacon` (grants the page). Auto-send additionally depends on egress being configured; without it the page still renders and the **Export** path is the primary channel (see §4).
**Relates to:** ADR 0012 D5 (beacon shape/fields), ADR 0009 (cloud-linked tenant evidence offload), ADR 0011 (Product Cortex feedback loop), ADR 0007 (data-at-rest / anchor honesty).

---

## 0. The one design decision that makes this trustworthy

A privacy-conscious SOC operator does not trust a telemetry toggle. They trust **seeing the exact bytes that leave**. So the entire screen is built around one move: **render the actual `beacon.json` next to the toggle, live, from this device's real values** — not a marketing description of "anonymous product data," the literal payload. Off by default; one toggle; the toggle *is* the consent because the evidence is already on screen; revocable in one click; never bundled with any other setting; no pre-checked box, no "recommended," no nag anywhere else in the product.

That is the whole differentiator (§9): Defender/Sentinel/Fortinet ship product telemetry **opt-out or silent**. HookProbe ships it **opt-in with a live preview of the payload** — the only posture consistent with the sovereignty pitch.

---

## 1. What ships (verbatim to the operator, no euphemism)

The beacon carries **only product-lifecycle signals** — how the *release* is behaving, never what the *network* is doing. The screen states both the allow-list and the deny-list in plain words, because "what we don't send" is what earns trust.

**Sent (the live `beacon.json`):**

| Field | Shown-as label | Meaning surfaced in UI |
|---|---|---|
| `schema` | Schema | `hookprobe.beacon/1` — the payload contract version. |
| `beacon_id` | Beacon ID | A **salted hash**, not your device ID. Labelled inline: *"one-way — not reversible to your device or serial."* |
| `image_version` | Release | e.g. `2026.7.1` — the release we're trying to learn about. |
| `device_class` | Platform class | e.g. `rk3588` — hardware family, not a serial. |
| `profile` | Profile | e.g. `edge-pro` — the image profile. |
| `arch` | Architecture | `arm64` / `amd64` / `riscv64`. |
| `uptime_hours` | Uptime | How long since boot — did the release stay up. |
| `boot` | Boot verdicts | `{ healthy, unhealthy, rollbacks }` — greenboot outcomes (`supervisor` health-gate). |
| `health` | Module health | `{ healed, failed, shed, reverted }` — `HealthState` roll-up. |
| `qsecbit_avg` | QSecBit (average) | A single 0–1 resilience number, **aggregate only** — no events behind it. |
| `consent` | Consent tag | `product-health-beacon/opt-in` — records that you opted in. |
| `ts` | Timestamp | When this beacon was assembled. |

**Never sent (stated as a hard deny-list on the screen):**
IP addresses · hostnames · MACs · flows/pcap · detections/alerts · IOCs · rules · user or customer data · file paths · configs · geolocation. The screen says: *"This beacon cannot carry security telemetry — the fields above are the entire schema; there is no free-text field."*

**Live preview = these fields, filled from this device right now.** Example rendering:

```json
{
  "schema":        "hookprobe.beacon/1",
  "beacon_id":     "b7f3d2…a91c",          // salted SHA-256 — not reversible to your device
  "image_version": "2026.7.1",
  "device_class":  "rk3588",
  "profile":       "edge-pro",
  "arch":          "arm64",
  "uptime_hours":  412,
  "boot":   { "healthy": 37, "unhealthy": 0, "rollbacks": 0 },
  "health": { "healed": 3, "failed": 0, "shed": 1, "reverted": 0 },
  "qsecbit_avg":   0.94,
  "consent":       "product-health-beacon/opt-in",
  "ts":            "2026-07-03T12:00:00Z"
}
```

The preview is **generated from the same code path that assembles the real beacon** — never a hand-written mock — so "what you see is what leaves" is literally true. When disabled, `consent` reads `"none"` and the preview is shown for inspection but nothing is transmitted.

---

## 2. The consent screen — copy proposal

Administration → **Feedback & Diagnostics**. Two panels: a plain-language header + the toggle on the left, the live payload on the right. Copy below is the proposed final string set.

- **Page title:** `Feedback & Diagnostics`
- **Subtitle:** `Help improve HookProbe OS by sharing how this release behaves — nothing about your network.`
- **Toggle label:** `Send the product-health beacon`
- **Toggle helptext (OFF):** `Off. This device sends nothing. Turn on to share release health; see exactly what leaves on the right.`
- **Toggle helptext (ON):** `On since <date>. Sends once/day and on boot-health change. Turn off any time — takes effect immediately.`
- **Allow-list caption (above preview):** `This is the entire payload. See exactly what leaves this device:`
- **Deny-list line:** `Never included: IPs, hostnames, flows, detections, IOCs, rules, files, users, or any customer data. There is no free-text field.`
- **Beacon-ID inline note:** `Beacon ID is a salted one-way hash — it cannot be reversed to your device or serial.`
- **Export button:** `Export diagnostics file` · helptext: `Download this exact beacon.json to attach to a GitHub issue. Works with no connectivity.`
- **Revoke affordance:** the same toggle, flipped. No separate "delete my data" maze — the honest statement is: `Turning off stops all future beacons. Past beacons are aggregate and unlinkable by design.`

**No dark patterns, enforced by spec:** no default-on, no pre-checked box, no "Recommended" tag, no interstitial that nags on turning off, no bundling (this page contains *only* the beacon + export — nothing else lives here), symmetric affordance (turning off is exactly as easy as turning on, same control, no confirmation friction).

---

## 3. Wireframes

### 3.1 Disabled (default state — standalone)

```
┌ Administration › Feedback & Diagnostics ──────────────────────────────────────┐
│                                                                                │
│  Feedback & Diagnostics                                          mode: standalone │
│  Help improve HookProbe OS by sharing how this release behaves —               │
│  nothing about your network.                                                   │
│                                                                                │
│  ┌ Product-health beacon ─────────────┐  ┌ See exactly what leaves ──────────┐ │
│  │                                    │  │  This is the entire payload:      │ │
│  │   ( ●  OFF )  Send the beacon      │  │                                   │ │
│  │                                    │  │  {                                │ │
│  │   Off. This device sends nothing.  │  │   "schema": "hookprobe.beacon/1", │ │
│  │   Turn on to share release health; │  │   "beacon_id": "b7f3…a91c",  ← 1-way│ │
│  │   see exactly what leaves →        │  │   "image_version": "2026.7.1",    │ │
│  │                                    │  │   "device_class": "rk3588",       │ │
│  │   Never included: IPs, hostnames,  │  │   "profile": "edge-pro",          │ │
│  │   flows, detections, IOCs, rules,  │  │   "arch": "arm64",                │ │
│  │   files, users, customer data.     │  │   "uptime_hours": 412,            │ │
│  │   There is no free-text field.     │  │   "boot": {healthy:37,unhealthy:0,│ │
│  │                                    │  │            rollbacks:0},          │ │
│  │   ┌──────────────────────────────┐ │  │   "health": {healed:3,failed:0,   │ │
│  │   │  Export diagnostics file  ⤓  │ │  │             shed:1,reverted:0},   │ │
│  │   └──────────────────────────────┘ │  │   "qsecbit_avg": 0.94,            │ │
│  │   Download this exact file to      │  │   "consent": "none",              │ │
│  │   attach to an issue. No network   │  │   "ts": "2026-07-03T12:00:00Z"    │ │
│  │   required.                        │  │  }                                │ │
│  └────────────────────────────────────┘  └───────────────────────────────────┘ │
│                                                                                │
│  Beacon ID is a salted one-way hash — not reversible to your device or serial. │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Enabled (standalone, healthy)

```
┌ Administration › Feedback & Diagnostics ──────────────────────────────────────┐
│  Feedback & Diagnostics                                          mode: standalone │
│                                                                                │
│  ┌ Product-health beacon ─────────────┐  ┌ Last beacon (sent) ───────────────┐ │
│  │                                    │  │  {                                │ │
│  │   ( ●  ON )  Send the beacon   ●green│  │   "schema": "hookprobe.beacon/1", │ │
│  │                                    │  │   "beacon_id": "b7f3…a91c",       │ │
│  │   On since 2026-07-03. Sends       │  │   "image_version": "2026.7.1",    │ │
│  │   once/day and on boot-health      │  │   "device_class": "rk3588",       │ │
│  │   change. Turn off any time —      │  │   … (all fields, live) …          │ │
│  │   takes effect immediately.        │  │   "qsecbit_avg": 0.94,            │ │
│  │                                    │  │   "consent":                      │ │
│  │   Last sent: 2026-07-03 12:00 UTC  │  │       "product-health-beacon/opt-in",│
│  │   Next: ~24h · Status: delivered   │  │   "ts": "2026-07-03T12:00:00Z"    │ │
│  │                                    │  │  }                                │ │
│  │   ┌──────────────────────────────┐ │  │                                   │ │
│  │   │  Export diagnostics file  ⤓  │ │  │  This is exactly what was sent.   │ │
│  │   └──────────────────────────────┘ │  └───────────────────────────────────┘ │
│  └────────────────────────────────────┘                                        │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Cloud-linked (the additional, separately-consented offload)

```
┌ Administration › Feedback & Diagnostics ──────────────────────────────────────┐
│  Feedback & Diagnostics                                        mode: cloud-linked │
│                                                                                │
│  ┌ Product-health beacon (this device) ┐  ┌ Live payload ───────────────────┐ │
│  │   ( ●  OFF )  Send the beacon        │  │  { … same 12 fields … }          │ │
│  │   Your choice on this device. Off.   │  └──────────────────────────────────┘ │
│  │   [ Export diagnostics file  ⤓ ]     │                                       │
│  └──────────────────────────────────────┘                                       │
│                                                                                │
│  ┌ Tenant evidence offload · ADR 0009 ──────────────────── consented ✓ ───────┐ │
│  │  Managed by your MSSP tenant policy.                                        │ │
│  │  Status: active · endpoint: tenant-clickhouse (acme-mssp)                   │ │
│  │  Consented at enrollment on 2026-05-11 by admin@acme.  [View terms]         │ │
│  │  This is a separate channel from the beacon above and is governed by your   │ │
│  │  tenant agreement, not this toggle. To change it, see Enrollment & mode.    │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────┘
```

The two channels are **visually and semantically separated**: the beacon is *this device's local opt-in*; the offload is a *tenant-scoped, enrollment-time consent* the operator already gave, shown read-only with provenance (who consented, when) and a link to change it where it was granted (Administration → Enrollment & mode), never silently re-toggled here.

---

## 4. States (capability + consent-state rendering)

Rendered purely from `feedback_beacon` grant + consent-file presence + last-send outcome. Never a broken button.

| State | Trigger | Rendering |
|---|---|---|
| **Disabled (default)** | No consent file | Toggle OFF; preview shows `consent:"none"`; Export always live. |
| **Enabled — healthy** | Consent file present, last send OK | Toggle ON with green dot; "Last sent / Next / delivered"; preview = last payload. |
| **Enabled — degraded (send failed)** | Consent file present **but** service/egress failed | Toggle stays ON (honest: your consent is intact); **amber** banner: *"Beacon on, but the last send failed — endpoint unreachable / offline. Enforcing your last choice; will retry. Export instead ⤓."* Never silently flips off. |
| **No egress (air-gapped)** | `feedback_beacon` granted, no egress in manifest | Toggle **greyed-with-reason**: *"No network egress configured on this device — use Export to share diagnostics."* Export is promoted to the primary action. |
| **Capability not granted** | Manifest lacks `feedback_beacon` | Page hidden from Administration nav (capability-gated, per house rules) — not shown greyed. |
| **Offline / degraded mode** | Global degraded state | Page shows the mode badge *"degraded — enforcing last approved state"*; if beacon was ON, beacons queue locally and send on reconnect; Export works regardless. |

Key honesty rule: **a failed send never toggles consent off.** Consent is the operator's declared intent; the reconciler enforces it and reports the delivery truth separately (amber), exactly like every other intent/plan surface in Mission Control.

---

## 5. The air-gapped export path

Same screen, same button, zero connectivity required. **`Export diagnostics file`** assembles the identical `beacon.json` (from the same code path as the live preview) and hands it to the browser as a download: `beacon-<image_version>-<ts>.json`. The operator attaches it to a GitHub issue by hand. No transport, no account, no egress — fully consistent with the standalone invariant. This is the honest closing of ADR 0012 D2's "standalone installs are invisible to the promotion loop" gap: the operator can *choose* to contribute a single file, on their terms, with no daemon phoning home.

Export is available in **every** state (even disabled, even air-gapped, even degraded) because exporting a file you can read first is never a privacy risk — you see it before you send it.

---

## 6. Where beacon status surfaces elsewhere (and where it must not)

**One quiet line, one place: Administration → Edge Nodes.** On the per-device row, a single muted status chip:

```
Feedback beacon:  ● on · last sent 2026-07-03      (or)   ○ off
```

Clicking it deep-links to `/admin/feedback`. That is the *entire* ambient footprint.

**Explicitly nowhere else.** Nothing on Mission Control. No orb annotation, no notification, no "you could help us — turn on telemetry" card, no onboarding step, no first-boot prompt. This must never become a nag: the operator finds it when they go looking, and the product never asks twice. The absence of a prompt is itself part of the trust posture — a sovereignty product that begs for telemetry contradicts its own pitch.

---

## 7. Click-count audit (target ≤3 each)

**Enable the beacon**
| Path | Steps | Count |
|---|---|---|
| Nav | Administration → Feedback & Diagnostics → flip toggle ON | **3** |
| Copilot (⌘-K) | "turn on the product health beacon" → approve plan-as-diff | **2** |
| Deep-link from Edge Nodes chip | click chip → flip toggle | **2** |

The toggle **is** consent — the live payload is already on screen, so there is no extra confirmation step (adding one would be friction, not safety). Enabling = **≤3**. ✅

**Export the diagnostics file**
| Path | Steps | Count |
|---|---|---|
| Nav | Administration → Feedback & Diagnostics → Export diagnostics file | **3** |
| Copilot (⌘-K) | "export a diagnostics file" → download | **1–2** |

Exporting = **≤3**. ✅

**Revoke:** one click (flip the same toggle) from the page — symmetric with enabling, no confirmation gate.

---

## 8. Accessibility · i18n · reduced-motion

- **A11y:** the toggle is a native switch with `aria-checked` and a programmatic label tied to the helptext; the live payload is a labelled `<pre>` region marked as a document region (screen-reader can read the exact fields). The allow-list/deny-list are real text, not images. Focus order: title → toggle → export → payload. Colour is never the only signal — the ON/OFF word and the "delivered/failed" word carry the state alongside the green/amber dot.
- **i18n:** all copy externalised; the payload keys stay in English (they are the wire schema and must not be localised), but every *label and helptext* around them localises. The deny-list is a translated sentence, not a graphic. Numbers/timestamps locale-formatted in the UI while the JSON stays ISO-8601/canonical.
- **Reduced-motion:** the only motion is the toggle transition and the green "delivered" dot; both respect `prefers-reduced-motion` (instant state change, no pulse). No animated payload diffing.

---

## 9. Competitive note — why explicit-opt-in-with-live-preview is the differentiator

| Product | Product/usage telemetry posture | Operator sees the payload? |
|---|---|---|
| **Microsoft Defender XDR / Sentinel** | Cloud service; diagnostic/usage data governed by tenant + Microsoft privacy terms; largely **on by design**, tuned via broad org-level privacy settings, not a per-device payload preview. | No — described in policy docs, not rendered as bytes. |
| **Fortinet (FortiGate / FortiSOC / FortiAnalyzer)** | "FortiGuard/telemetry" and cloud-service data sharing typically **opt-out** or enabled to unlock features; controlled by a checkbox, not a payload view. | No. |
| **Most SaaS SOC tools** | Silent product analytics (SDKs), opt-out at best. | No. |
| **HookProbe OS** | **Off by default, single explicit opt-in, revocable in one click, air-gap export as a first-class equal path, and a live render of the exact `beacon.json` that leaves — generated from the same code that sends it.** | **Yes — the literal payload, live.** |

HookProbe is fewer-steps *and* more honest: enabling is ≤3 clicks (competitors bury telemetry in nested privacy panels), and the operator sees the exact 12-field payload rather than a policy paragraph. For a product whose entire pitch is **sovereignty / "no account, no cloud, air-gapped by default"**, opt-out or silent telemetry would be self-refuting. The live preview turns "trust us" into "verify us" — the single most trust-building move available, and one the incumbents structurally cannot copy without abandoning cloud-first defaults.

---

## 10. Summary of what this UX guarantees

- **Off by default**, one toggle, one page, no bundling, no dark patterns, no nag.
- **You see exactly what leaves** — the real `beacon.json`, live, from the same code path that sends it.
- **Only product-lifecycle signals**; a stated hard deny-list; no free-text field to leak into.
- **Air-gapped operators are first-class** — Export works with zero connectivity, in every state.
- **Cloud-linked offload is separate and honest** — shown as an already-consented, tenant-governed channel, never conflated with the local toggle.
- **Honest degraded states** — a failed send never flips your consent; the reconciler enforces intent and reports delivery truth separately.
- **≤3 clicks** to enable, **≤3 clicks** to export, **1 click** to revoke.
```

