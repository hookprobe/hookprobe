# Hookprobe UI Layouts & Technical Requirements

> Imported 2026-11-10 from the team's shared doc "Hookprobe UI Layouts & Technical Requirements" (revision 10), together with the "Hookprobe Wireframes" design canvas. `docs/architecture/MissionControl.md` stays canonical; this doc adds breakpoints, phone rules and the numbered requirements (TR, FR, DR, NFR). Repo-side decisions are recorded in the appendix at the end.

## Overview

HookProbe OS needs one UI, Mission Control. It runs on desktop, tablet and phone, and each user sees more or less of it depending on their role, the device's mode and what the hardware can do. The UI is served from the security device itself (browser → device, no cloud required). The visual and functional target is `docs/architecture/MissionControl.md`, which is the source of truth for this document.

Positioning, from the repo: *HookProbe OS is the operating system. SOC is its default workspace. Hardware only unlocks capabilities.*

**What the UI must do**

- Answer "Am I safe, what happened, is it handled?" in plain language, with no clicks.
- Present every module as a workspace over one evidence graph, not as a separate app.
- Let users state an intent, then review and approve a plan shown as a diff. A deterministic reconciler applies it.
- Adapt to **mode** (standalone, cloud-linked MSSP, self-hosted control plane) and to the device's signed **Platform Manifest** (capabilities).

**Personas** (from `docs/research/v2-customer-experience.md`)

| Persona | Who | Mode | Default depth | Main surfaces |
|---|---|---|---|---|
| Sam | Home or prosumer user, about 25 devices, not technical | Standalone | Layer 0 (calm, five pillars) | Calm home, Shield, My Network, Get Online, incident stories |
| Dana | SMB owner or IT generalist | Standalone or cloud-linked | Layer 0, one-click promotion | Same as Sam, plus segmentation, executive summary, audit export |
| Priya | MSSP analyst | Cloud-linked | Layer 2 (Pro view, all workspaces) | Mission Control, Investigate, Detect, Intelligence, Customers |
| Alex | Admin or installer | Any | Layer 1 or 2 | Zero-touch setup, Get Online, Administration |

**Three dials control what renders**

1. **Capability.** The manifest decides whether a control is shown, greyed out with a reason, or hidden. A control must never be broken or a no-op.
2. **Depth.** Layer 0 is the five pillars, Layer 1 is a workspace scoped to one thing, and Layer 2 is the full Pro view. The depth changes the vocabulary and density, never the data.
3. **Mode and RBAC.** Standalone hides fleet, tenant and business views. Cloud-linked adds a scope switcher (device, site, fleet, tenant).

**Current state.** The UI is built in `os/mission-control/` with Astro 7, SolidJS and TypeScript. It is compiled to static assets and served by the on-device server. Pages exist for Mission Control, Workspace, Observe, Detect, Investigate, Protect, Network (DNS, map), Automate, Intelligence, Customers, Business, Knowledge, Admin and Setup. Many of them still run on mock data stores.

## Information architecture

There are 14 workspaces plus the always-on Copilot. Users without Pro view see only the five pillars, and each pillar opens into a workspace when they need more. Every route accepts a device, site, fleet or tenant scope without changing its structure.

**Layer 0: five pillars (the calm home for Sam and Dana)**

| Pillar | Users' words | Opens into (Layer 1) | Routes |
|---|---|---|---|
| Shield | "Block the ads and junk" | Detect and Protect, DNS | `/network/dns` |
| My Network | "See and run my network" | Network/Gateway and Protect | `/network/map`, `/network/zones`, `/network/devices` |
| Get Online | "Get me online, fix my Wi-Fi" | Network/Gateway | `/network/wan`, `/network/wifi`, `setup.hookprobe.local` |
| Security you understand | "Am I safe, what happened, is it handled?" | Mission Control, Investigate | `/mission`, `/investigate/queue` |
| Timeline & Export | "It's my data" | Observe, Admin integrations | `/observe/events`, `/admin/settings` |

**Layer 2: full workspace inventory**

| # | Workspace | Purpose | Subpages | Standalone | Cloud-linked |
|---|---|---|---|---|---|
| 1 | Mission Control | What the system is doing right now | 12 cards: health, threat pulse, AI activity, incidents, fleet, customers, performance, AI timeline | Yes | Yes, any scope |
| 2 | Workspace | Recent and saved work | Recent incidents, customers and reports; saved searches and investigations; bookmarks; AI conversations; draft playbooks | Yes | Yes |
| 3 | Observe (Senzorium) | All incoming telemetry | Endpoints, network, DNS, HTTP, packets, NetFlow, syslog, events, sensors, assets, live stream | Yes | Yes |
| 4 | Detect (NAPSE) | Detections and rules | Threat feed, AI, behavioral, signature, Sigma, YARA, IOC, hunting, MITRE, rules, rule builder, rule testing | Yes | Yes |
| 5 | Investigate (AEGIS) | Turn alerts into stories | Queue, AI investigation, timeline, process tree, graph, evidence, packet replay, root cause, similar, recommendations, executive summary | Yes | Yes |
| 6 | Protect | Response and posture | Firewall, endpoint, network, quarantine, isolation, VPN, zero trust, policies, patch, compliance, risk | Yes | Yes |
| 6b | Network/Gateway | The device as the router or LAN | Get Online (WAN), Wi-Fi, device map, zones (bubbles), device trust, Apple/IoT ecosystem, DNS/Shield, segmentation flows (Pro) | Yes | Yes |
| 7 | Automate | Playbooks and workflows (SOAR) | Playbooks, AI agents, workflows, scheduled tasks, integrations, webhooks, API, notifications, approval queue, analytics | Yes | Yes |
| 8 | Intelligence (HYDRA) | Threat intelligence | CVEs, IOC, threat actors, malware, campaigns, MITRE, exploits, reputation, dark web, AI research, knowledge graph | Yes | Yes |
| 9 | Customers | Recursive multi-tenant portal | My org, managed customers, dashboard, assets, users, sites, billing, SLA, compliance, score, reports, API | No | Yes |
| 10 | Business | Commercial layer | Dashboard, licenses, billing, marketplace, quotes, usage, contracts, revenue, costs, SLA, AI cost, reports | Licensing only | Yes |
| 11 | Knowledge | Content and growth engine | Blog CMS, SEO AI, keywords, page and video generators, LinkedIn, newsletter, docs, wiki, runbooks, SOP, AI writer | Yes | Yes |
| 12 | Administration | Identity, infrastructure, OS lifecycle | Identity and access, infrastructure, OS lifecycle (builder, images, modules, provisioning, enrollment, edge nodes), telemetry fabric, AI models, logging, audit, backup, settings, feedback | Yes | Yes |
| 13 | AI Copilot | Overlay on every screen (⌘/Ctrl-K) | Ask, explain, predict, recommend, investigate, generate, automate, document, search, learn | Yes | Yes |

The device-local flows are not `/admin` routes. They are the first-boot captive **setup portal**, the persistent `setup.hookprobe.local` (Get Online for non-technical users) and the full console at `os.hookprobe.local`, all served over mDNS with a stable-IP fallback.

## Desktop layouts (1280 px and wider)

On desktop, every screen uses the same three-column shell: a left rail, a bento content grid and a right side panel that slides in. Each screen below lists its regions, components, data sources and required states. Endpoints marked *(exists)* are already called by the UI. The rest are proposed and need confirmation.

### Global shell

- **Top bar (56 px, full width).** From left to right: the organism status pill (QSecBit score with a protected or at-risk word; clicking it goes to `/mission`), the scope switcher (hidden in standalone), the command bar ("Ask anything…", ⌘/Ctrl-K), the mode badge (`standalone`, `cloud-linked` or `self-hosted`, plus online or "degraded, enforcing last approved state"), the notifications bell with a count, and the identity menu (user, RBAC role, Pro view toggle, sign out).
- **Left rail (212 px, collapses to a 64 px icon rail).** The brand at the top, then 13 workspace items with icons and labels, the active item highlighted. Below them sit the QSecBit mini-card (score and sparkline) and a device footer showing the tenant, `os.hookprobe.local` and a status dot. At Layer 0 the rail shows the five pillars instead.
- **Content area.** A 12-column bento grid with 16 px gutters and 24 px outer padding. Each workspace has a header with the workspace name, breadcrumb, sub-tabs for its subpages, and primary actions on the right.
- **Right side panel (400 px, overlay).** Holds the AI explanation panel (why, confidence, evidence, model, related events), the record detail drawer, and the Copilot conversation. It closes with Esc.
- **Command palette (modal, 640 px wide, centered).** Free-text intent, navigation results, and an answer with evidence, or a **plan as a diff** with Approve and Reject buttons.
- **Global banners.** Offline or degraded mode, "Sample data" (the existing `SampleDataNotice`), retention warnings and failed reconciliations.

The rail and top bar never change between workspaces. Only the bento content and the side panel's contents do.

### Calm home (Layer 0, `/` for standalone)

- **Hero row:** the organism orb (about 220 px) on the left, with the verdict sentence on the right ("You're protected. Nothing needs you right now."), the last-checked time, a heartbeat sparkline, and a "What happened today" button.
- **Two cards:** Shield (ads and trackers blocked today, malware sites stopped, Manage) and My Network (devices total and online, counts per zone, devices without a name, Open map).
- **Needs you:** the only queue on this screen. When it is empty, it says so and shows what the system did on its own, with a "See what we did and why" link.
- **Footer links:** Get Online, Timeline & Export, Pro view.
- **Data:** `/api/qsecbit`, `/api/stats`, `/api/dns`, `/api/devices`, `/api/actions` *(exist)*, with live updates over `/api/stream` (SSE).
- **States:** protected, needs you, critical, offline (last verdict plus an honest banner), first run (empty).

### 1. Mission Control (`/mission`, Layer 2 landing)

- **Row 1:** Global health (the orb with a QSecBit breakdown ring, 4 columns), Threat pulse (velocity, level, attacks blocked, top families, trend, 4 columns), AI activity (decisions by NAPSE, HYDRA and AEGIS, escalations, autonomous fixes, confidence, 4 columns).
- **Row 2:** Active incidents (priority queue, 6 columns), Autonomous actions (what the system did and why, 6 columns).
- **Row 3:** Infrastructure and global map (edges, connections, blocked attacks, 8 columns), Performance (ingest rate, latency, headroom, 4 columns).
- **Row 4:** AI timeline (chronological decisions, 12 columns).
- **Linked mode only:** Fleet health (healthy, needs attention, critical) and Customer health (one card per tenant).
- **Rule:** every number links into the evidence graph, and every card opens its full view.
- **Data:** `/api/qsecbit`, `/api/incidents`, `/api/actions`, `/api/engines`, `/api/health`, `/api/evidence/stats` *(exist)*.

### 2. Workspace (`/workspace`)

- A grid of lists: recent incidents, customers and reports; saved searches and investigations; bookmarks and favorites; AI conversations; draft playbooks.
- Each row shows the type icon, title, scope, last touched and a link to the live object. Users can filter by type and pin items.
- **Empty state:** "Nothing here yet" with three suggested first actions.

### 3. Observe (`/observe/*`)

- **Header:** the retention window indicator (for example "raw packets kept 7 days") and per-interface roles (out-of-band or inline).
- **Body:** a source sidebar (endpoints by OS, network, DNS, HTTP, packets, NetFlow, syslog, events, sensors, assets) beside a virtualized event table with columns for time, source, entity, type, severity and summary. A **live stream** toggle tails new events.
- **Drill-down drawer:** flow → session → packets → raw pcap. Data outside the retention window is marked, with an option to offload it.
- **Data:** `/api/flows`, `/api/dns`, `/api/devices`, `/api/stream` *(exist)*; events, assets and pcap endpoints are proposed.

### 4. Detect (`/detect/*`)

- **Threat feed:** severity filters, a MITRE tactic filter and engine chips. Each detection card shows its title, severity, ATT&CK technique, affected asset, engine, confidence and time, with Open story and Open graph actions.
- **Rules and Rule builder:** a rules table (name, type such as Sigma, YARA or Suricata, status, hits, last hit), a split-pane editor (code on the left, test results on the right), and Rule testing against a sample.
- **MITRE:** an ATT&CK matrix heatmap of hits.
- **Data:** `/api/detections` *(exists)*. Capability-gated on `ids`.

### 5. Investigate (`/investigate/*`)

- **Queue (list):** incidents sorted by priority, with status, assignee, affected assets and age.
- **Incident story (detail, the key screen):**
    - Left, 8 columns: the attack timeline as a vertical story, a process tree, and a graph view of the evidence nodes.
    - Right, 4 columns: the "Why AEGIS decided this" panel (confidence, evidence list, alternative hypotheses, model used), context (ATT&CK, CVE, Sigma or YARA hits, related campaigns), and the **proposed plan diff** with Approve, Reject and Edit buttons.
    - Tabs: Evidence, Packet replay, Root cause, Similar incidents, Recommendations, Executive summary (printable).

- **Data:** `/api/incidents`, `/api/incidents/:id`, `/api/incidents/:id/timeline`, `/api/incidents/:id/processes`, `/api/evidence/graph`, `/api/planner/incidents/:id/explain`, `/api/planner/propose`, `/api/planner/approve` *(exist)*.

### 6. Protect (`/protect/*`)

- **Posture header:** per-interface mode (out-of-band or inline) and fail-open or fail-closed per segment.
- **Firewall:** a rules table with order, match, action, hits, source (manual, AEGIS or playbook) and capability gate.
- **Isolation and quarantine:** isolated assets, with reason, time and release action.
- **Compliance and risk:** control coverage as stacked bars and a risk register.
- **Rule:** active controls are gated by the manifest. Without the grant they render greyed out with the reason, in alert-only mode.
- **Data:** `/api/actions`, `/api/actions/revoke` *(exist)*.

### 6b. Network/Gateway (`/network/*`)

- **Get Online (WAN):** link cards (type PPPoE, DHCP or LTE, status, speed, health), multi-WAN failover order, and a simple or advanced toggle.
- **Wi-Fi:** SSID cards (bands, clients, guest), a channel and DFS panel (Pro).
- **Device map:** a force-directed or grouped canvas (smooth at about 250 nodes), each device shown as an icon with name, zone color and online state. A side list offers search and filters. Clicking a device opens a drawer with identity (Fingerbank), trust, zone, traffic, and Block, Trust and Rename actions.
- **Zones (bubbles):** zone columns or clusters that users can drag devices between, with an equivalent keyboard "Move to…" action, AI suggestions and Quarantine.
- **DNS/Shield:** blocked counts today, top blocked domains, per-zone profiles and allow or deny lists.
- **Segmentation flows (Pro):** a read-only or editable view of generated OVS, VLAN and nftables artifacts.
- **Data:** `/api/devices`, `/api/dns` *(exist)*. Gated on `wan`, `dhcp`, `dns`, `wifi_ap` and `openvswitch`.

### 7. Automate (`/automate/*`)

- **Playbooks:** each playbook is a horizontal CI/CD-style pipeline (detect → validate → contain → notify → recover → verify → close). Every stage shows its state and an autonomy chip (auto or needs approval), and opens AEGIS's rationale.
- **Approval queue:** pending actions with their diff, requester, risk, and Approve or Reject.
- **Integrations and webhooks:** connector cards, plus an API token table.

### 8. Intelligence (`/intelligence/*`)

- **CVEs:** a table with CVE ID, CVSS, exploitability, affected assets in scope and status. A detail view lists the exposed assets.
- **IOC, actors, malware, campaigns:** entity lists, and detail pages with a knowledge-graph mini view.
- **Data:** `/api/exploitability` *(exists)*; STIX/TAXII and MISP feeds.

### 9. Customers (`/customers/*`, linked only)

- A tenant tree on the left (recursive nesting), and on the right the selected customer's dashboard: security score, SLA, assets, sites, users, compliance and reports.
- Switching customer changes the scope everywhere. Cross-tenant views are aggregates only.

### 10. Business (`/business/*`)

- A KPI row (revenue, licenses, usage, AI cost), plus tables for licenses, quotes, contracts and invoices. Marketplace is a card grid of signed modules (install shows the capabilities the module will get).
- Standalone mode shows only the licensing panel.

### 11. Knowledge (`/knowledge/*`)

- A content list (blog, runbooks, SOP, wiki) and a two-pane editor (Markdown on the left, preview on the right) with an AI Writer side panel that can cite incidents or evidence nodes. SEO and keyword tools appear as panels.

### 12. Administration (`/admin/*`)

- A settings-style layout: a secondary nav list (Identity and access, Infrastructure, OS lifecycle, Telemetry fabric, AI models, Logging, Audit, Backup, Settings, Feedback) beside a form or table pane.
- **Edge nodes:** a Platform Manifest viewer (hardware, capabilities, crypto posture), OS version and channel, storage and retention fill, and rollout rings (canary → ring → fleet).
- **AI models:** endpoint (Ollama or any OpenAI-compatible service), confidence thresholds and autonomy per playbook.
- **Feedback and diagnostics:** a consent screen that shows the exact `beacon.json`, an opt-in toggle that is off by default, and Export diagnostics.

### 13. AI Copilot (overlay)

- The command palette, with an expanded conversation in the right panel. Answers show cited evidence chips. Plans render as a diff with Approve and Reject. The panel shows the active scope (device, site, fleet or tenant).
- **Data:** `/api/planner/status`, `/api/planner/propose`, `/api/planner/approve` *(exist)*.

## Web: tablet and compact layouts (768–1279 px)

On tablets and compact windows the shell is the same, with less room. The rail collapses, the bento grid reflows from 12 to 8 columns, and the side panel becomes a full-height sheet. No feature is removed. Only the layout changes.

**Shell changes**

| Element | Desktop (1280 px and wider) | Compact (1024–1279 px) | Tablet (768–1023 px) |
|---|---|---|---|
| Left rail | 212 px with labels | 64 px icons, labels on hover | Hidden; opened from a hamburger menu as an overlay drawer |
| Top bar | Full: pill, scope, command bar, mode, bell, identity | The command bar shrinks to an icon plus ⌘K hint | Pill, command icon, bell, identity; scope and mode move into the identity menu |
| Bento grid | 12 columns | 8 columns; 4-column cards become 4 or 8 | 4 columns; cards stack two per row |
| Side panel | 400 px overlay | 400 px overlay | Full-height sheet, 80% width |
| Tables | All columns | Low-priority columns hidden, available in the row drawer | Rows become cards with 3–4 key fields |
| Split editors (rules, knowledge) | Side by side | Side by side, 50/50 | Tabs: Edit and Preview |

**Screen-specific rules**

- **Mission Control:** row 1 becomes the orb card at full width, with threat pulse and AI activity side by side. The map card keeps a 16:9 ratio.
- **Incident story:** the right-hand "Why" and plan column moves below the timeline as a sticky "Review plan" bar at the bottom of the screen.
- **Device map:** the canvas stays, and the device list becomes a bottom sheet. Touch targets are at least 44 px. Users can drag and drop between zones on touch, with long-press as an alternative to the keyboard.
- **Playbook pipelines:** scroll horizontally with snap points per stage.

### Zero-touch setup portal (any screen size)

This is the first-boot flow (ADR 0010). It is usually opened on a **phone** after joining the `HookProbe` Wi-Fi, so it is designed mobile-first and centered at most 560 px wide on larger screens.

1. **Captive portal opens.** Full-screen Copilot greeting, with no form and no IP address to type.
2. **Internet.** "I see a link on eth0 already pulling a lease. Use it as your internet?" with Yes, PPPoE and Advanced buttons. Advanced shows only the options the manifest grants (PPPoE, VLANs, multi-WAN, DoH, mesh).
3. **Wi-Fi.** Network name and password, with a strength meter.
4. **Launch.** One plan shown as a diff to approve. A progress state polls WAN readiness, then redirects to `os.hookprobe.local`. The connection never drops (same SSID, same `10.66.0.1`).
5. **Optional:** set a passphrase (which changes the encryption anchor from software to passphrase).

The target is online in 4 steps or fewer. **States:** no link detected, wrong PPPoE credentials, slow or no WAN, success. Afterwards the same UI stays at `setup.hookprobe.local` as Get Online for non-technical users.

## Mobile app layouts (under 768 px)

The repo has **no native mobile or desktop app**. I recommend shipping mobile as an installable PWA of the same Mission Control build, served from the device. On a phone the UI should focus on checking status, approving actions and handling one device at a time, not building rules. The authoring screens are still available but show a "best on a larger screen" note.

**Navigation pattern**

- **Top bar (52 px):** the organism pill on the left, the Copilot icon and the bell on the right. No scope switcher: scope is picked inside Copilot or the identity sheet.
- **Bottom tab bar (64 px, 5 tabs):**
    - Layer 0: Home, Shield, My Network, Get Online, More.
    - Layer 2: Mission, Investigate, Network, Approvals, More.

- **More** opens a full-screen list of every other workspace, plus Pro view, Settings and Sign out.
- **Copilot** opens as a full-screen sheet with a large text input and quick-intent chips ("What happened today?", "Block a device", "Is my Wi-Fi ok?").

**Key screens**

| Screen | Mobile layout | Primary actions |
|---|---|---|
| Calm home | Orb (about 160 px) with the verdict sentence under it; Shield and My Network cards stacked; Needs-you list | Open story, Approve |
| Notifications and approvals | A list grouped by Incidents, Approvals and Warnings; each approval opens a diff sheet | Approve, Reject (swipe or buttons; never swipe only) |
| Incident story | A single-column vertical timeline; the "Why" panel is collapsible; the plan bar sticks to the bottom | Approve plan, Isolate device |
| My Network | List-first (search, zone filter chips), with the map as a secondary tab | Rename, Move to zone, Trust or Block |
| Device detail | Full-screen: identity, zone, trust, traffic sparkline, recent events | One toggle per action |
| Shield | Counters, top blocked domains, per-zone profile picker | Pause blocking for 15 min, Allow domain |
| Get Online | The same steps as the setup portal | Change WAN, Change Wi-Fi password |
| Mission Control (Pro) | Cards in one column, in priority order: health, incidents, autonomous actions, threat pulse, AI timeline | Drill into any number |
| Detect, Intelligence and Observe lists (Pro) | Card lists with filter chips and infinite scroll | Open detail |

**Mobile rules**

- Touch targets are at least 44 × 44 px, the base font is 16 px, and everything is usable one-handed: primary actions sit in the bottom third of the screen.
- Safe-area insets apply (notch and home indicator). Pulling down refreshes, as well as the live SSE updates.
- Push notifications for incidents and approvals in a PWA need Web Push, which requires the device to be reachable or a cloud-linked relay. Standalone mode falls back to in-app notifications only.

## Design system foundations

The look is a dark command center: calm and dense, with neon used only to signal something. The organism orb is the one bold element. The tokens below come from `os/mission-control/src/styles/global.css`.

**Breakpoints and grid**

| Name | Width | Columns | Gutter | Outer margin |
|---|---|---|---|---|
| Mobile | Under 768 px | 4 | 12 px | 16 px |
| Tablet | 768–1023 px | 4 (cards two per row) | 16 px | 20 px |
| Compact | 1024–1279 px | 8 | 16 px | 24 px |
| Desktop | 1280–1919 px | 12 | 16 px | 24 px |
| Wide | 1920 px and wider | 12, max content 1760 px | 16 px | 32 px |

**Color tokens (one color language)**

| Token | Value | Meaning |
|---|---|---|
| `--hp-canvas` / `--hp-void` | #0a0a0f / #050508 | Page background |
| `--hp-surface` / `--hp-surface-elevated` | #12121a / #16161f | Panels, raised panels |
| `--hp-border` | white at 7% | Hairline panel borders |
| `--hp-cyan` (also `--hp-blue`) | #00B4FF | Primary actions, links, information |
| `--hp-green` | #00FF9D | Healthy, protected, success |
| `--hp-purple` | #A855F7 | AI and MITRE |
| `--hp-amber` | #ffaa00 | Needs attention |
| `--hp-orange` | #ff6b00 | High severity |
| `--hp-red` | #FF6B6B | Critical |
| `--hp-grey` | #5a5a6a | Inactive |
| `--hp-text-primary` / `secondary` / `muted` | #e0e0e0 / #9a9aab / #7a7a8a | Text levels |

Color is never the only signal. Every status pairs a color with a word and an icon.

**Typography**

- **UI face:** the system stack (`-apple-system`, Segoe UI, Inter). **Brand and data face:** JetBrains Mono, for numbers, IDs, hashes and code.
- **Scale:** base 14 px on desktop and 16 px on mobile. Labels are 11 px uppercase with tracking. KPI numbers are 28–34 px, weight 800. Page titles are 20 px, weight 600.

**Shape and motion**

- **Radii:** 4 px (chips), 8 px (cards, the default), 12 px (large panels and sheets). Spacing steps are 4 and 8 px, with a 16 px default gap.
- **Glows:** cyan, green and purple are used only on signal elements (the orb, live indicators).
- **Motion:** counters, threat pulse and heartbeat are "living, not refreshing." Everything degrades to static under `prefers-reduced-motion`.

**Core component inventory**

Organism orb · Status pill · Mode badge · Scope switcher · Command palette · Bento card (title, KPI, sparkline, drill link) · Radial gauge · Sparkline · Stacked bar · Heatmap (MITRE) · Timeline (story) · Node graph · Device map canvas · Data table (virtualized, column priority) · Card list (mobile tables) · Filter chips · Severity badge · AI explanation panel · Plan diff viewer (approve or reject) · Pipeline stage · Side panel and sheet · Bottom tab bar · Banner (offline, sample, retention) · Capability-gated control (enabled, greyed with a reason, hidden) · Empty, loading and error states.

## Technical requirements

The UI is a static Astro and SolidJS build served by the on-device kernel server (heqk, ADR 0047), with no Node at runtime. It must deliver sub-second interactions on edge hardware, receive live SSE updates, and keep working fully offline.

**Platform and stack**

| ID | Requirement |
|---|---|
| TR-01 | The stack is Astro 7, SolidJS 1.9 and TypeScript, built to static assets (ADR 0001). |
| TR-02 | Served by the device over HTTPS (`mcserve.rs`, `tlshost.rs`, ADR 0051) at `os.hookprobe.local` via mDNS, with a stable-IP fallback. |
| TR-03 | No CDN or external runtime dependency. Fonts and icons are bundled so the UI works air-gapped. |
| TR-04 | Browser support is the last 2 versions of Chrome, Edge, Firefox and Safari, including iOS Safari and Android Chrome. |
| TR-05 | Mobile ships as an installable PWA (manifest and service worker caching static assets only, never security data). Native or desktop wrappers are optional and not in scope until confirmed. |

**Functional**

| ID | Requirement |
|---|---|
| FR-01 | Implement the global shell (top bar, rail, side panel, command palette) on every route. |
| FR-02 | Implement every route in the MissionControl.md route map, each accepting a `device`, `site`, `fleet` or `tenant` scope parameter. |
| FR-03 | Show the calm home (Layer 0) by default for standalone devices and the Pro view (Layer 2) for cloud-linked MSSP users. The Pro view toggle persists per user, and RBAC can pin a role to a layer. |
| FR-04 | Gate every control on capabilities from the signed Platform Manifest: render it, grey it out with a reason, or hide it. |
| FR-05 | Adapt to the mode: standalone hides scope, Customers and full Business; offline shows "degraded, enforcing last approved state." |
| FR-06 | Follow the drill-down contract: every aggregate number links to its evidence graph node. No dead-end numbers. |
| FR-07 | Every AI decision or action opens the AI explanation panel (why, confidence, evidence, model, related events). |
| FR-08 | The intent flow goes Copilot → proposed plan diff → approve or reject → the reconciler applies → the UI shows verification. Nothing is applied without an approval or a matching autonomy policy. |
| FR-09 | Show evidence and retention indicators wherever raw data is referenced, with an offload option once data is outside the retention window. |
| FR-10 | The zero-touch setup portal reaches "online" in 4 steps or fewer, with a handoff that keeps the connection, plus WAN-readiness polling. |
| FR-11 | The Feedback and diagnostics beacon is off by default, shows the exact payload, and offers an export file that works air-gapped. |

**Data and API** (the `legacy/linux-tier/crates/hookprobe-api` contract is the interface spec)

| ID | Requirement |
|---|---|
| DR-01 | Use the existing REST endpoints: `/api/session`, `/api/logout`, `/api/health`, `/api/qsecbit`, `/api/stats`, `/api/engines`, `/api/incidents` (with `/:id`, `/timeline`, `/processes`), `/api/detections`, `/api/devices`, `/api/flows`, `/api/dns`, `/api/tls`, `/api/actions` (with `/revoke`), `/api/evidence/graph`, `/api/evidence/stats`, `/api/exploitability`, `/api/reports`, `/api/planner/{status,propose,approve,incidents/:id/explain}`, `/api/provision/launch`. |
| DR-02 | Live updates come over `GET /api/stream` (SSE) as deltas for QSecBit, incidents and actions. It reconnects automatically, and the UI keeps the last fetched values while disconnected. |
| DR-03 | Each workspace has a mock store (`*Mock.ts`) and a live store (`*Live.ts`). The "Sample data" banner is required whenever a mock store is rendered. |
| DR-04 | New endpoints are needed for: Observe events, assets and pcap; Detect rules CRUD and testing; Protect firewall and policies; Network WAN, Wi-Fi and zones; Automate playbooks and approvals; Intelligence entities; Customers tenancy; Business; Knowledge; Admin. These need sign-off. |
| DR-05 | Lists use cursor pagination and server-side filtering. Large tables are virtualized in the client. |

**Non-functional**

| ID | Area | Requirement |
|---|---|---|
| NFR-01 | Performance | Interactions under 1 s on Pi 5, RK3588 and N100. First load of the calm home under 2 s on the LAN. |
| NFR-02 | Performance | The device map stays smooth (60 fps target) at about 250 nodes on a Pi. Live updates never cause a full re-render. |
| NFR-03 | Performance | JS budget per route of about 150 KB gzipped (proposed; to be confirmed against current builds). |
| NFR-04 | Accessibility | WCAG 2.2 AA; color is never the only signal; full keyboard access, with drag optional; screen reader labels on the orb, charts and graphs. |
| NFR-05 | Accessibility | Honor `prefers-reduced-motion`; motion is never needed to understand anything. |
| NFR-06 | i18n | All strings externalized; numbers, dates and units localized; RTL mirroring of the bento and map layouts. |
| NFR-07 | Security | Sign-in with the per-image owner key (the device stores only a salted verifier); session cookies are HttpOnly, Secure and SameSite=Strict; CSRF protection on mutations; strict CSP. |
| NFR-08 | Security | Tenant isolation: cross-tenant views are aggregates only, scoped RBAC is enforced server-side, and the UI never trusts its own hiding of controls. |
| NFR-09 | Privacy | No telemetry leaves the device unless the user opts in. Security data is never in the beacon. |
| NFR-10 | Resilience | Offline and degraded states for every screen; local protection controls (DNS, zones, isolation) keep working without the cloud. |
| NFR-11 | Quality | End-to-end gates: `os/kernel/tools/mc-e2e.sh` (API plus browser) in QEMU and `mc-e2e-metal.sh` on hardware, plus visual regression at 4 breakpoints. |

## Open questions and assumptions

- **Desktop app.** The repo has no native desktop app. Do we need a wrapper (for example Tauri), or is the desktop browser layout enough?
- **Mobile app.** Is a PWA acceptable, or is a native iOS and Android app required? Native would need its own requirements (store builds, push, device pairing).
- **Mobile scope.** Is mobile for monitoring, approvals and the network only, as assumed here, or full parity including rule authoring?
- **Reference mockup.** The spec points to `~/hookprobe-v2-dashboard.png`, which is not in the repo. Can it be added so the screens match it?
- **Light theme.** The spec is dark only. Is a light theme in scope?
- **Workspaces to design first.** Business, Knowledge and Customers are large and only for linked mode. Should the first round cover the calm home, Mission Control, Investigate, Network/Gateway and setup?
- **New endpoints.** Confirm the proposed endpoints in DR-04 and the JS budget in NFR-03.
- **Automate and Intelligence bodies.** MissionControl.md notes these §7 and §8 sections still need updating after HYDRA moved to Intelligence.

## Sources

All from [hookprobe/hookprobe](https://github.com/hookprobe/hookprobe), read on 10 November 2026: `README.md`, `CLAUDE.md`, `docs/architecture/MissionControl.md`, `docs/research/v2-customer-experience.md`, `onboarding/setup-ui/README.md`, `os/mission-control/` (pages, components, stores, `styles/global.css`, `package.json`).

## Appendix: implementation decisions (added in the repo, 2026-11-10)

These record what was agreed while integrating the wireframes. They refine the sections above; they do not change them.

**Routes.** `/network/map` keeps its name; the My Network pillar lands on `/network/zones`, and the wireframe's Zones / Map / List switch moves between `/network/zones`, `/network/map` and `/network/devices`. `/investigate/queue` stays the list; `/investigate/:id` is one incident (matches `/api/incidents/:id`). Network/Gateway is its own workspace (§6b), between Protect and Automate.

**Approve has three honest states (FR-08).** After Approve the plan is **Staged** (nothing is live). It moves to **Applying** while the reconciler runs, and to **Applied and verified** only once AEGIS reports success. A failure says so, names the step that failed, and offers Retry. The UI never claims a state the device did not report. One shared `PlanDiff` component implements this everywhere.

**Layer 0 screens (PR 2).** `/observe/events` is Timeline & Export (the plain-words story, with real CSV / JSON / print export); the raw Pro Observe table moved to `/observe/live`. On heqk, durable configuration (device zones and names in DEVICES.TXT, Wi-Fi and WAN in WIFI.TXT / WAN.TXT, Shield lists) changes only by re-signing the file (ADR 0053 S7), so those controls render greyed with that reason; the time-bounded actions (Isolate 1 h, Hold 1 h, Pause 1 h, Allow 1 h) stay live. Get Online shows no speed test: the device cannot measure one, so no number is shown. While the device clock is unset, events are grouped as "since this device started" with times since boot.

**Pro batch 1 (Mission Control + Investigate).** Mission Control follows the wireframe's bento rows with only device-measured values: QSecBit, rules armed, devices watched, frames dropped, detection families, real engine hit counts, open incidents, time-bounded actions with their audit reason, WAN / device / LAN / Wi-Fi, packets seen / forwarded / dropped and retention. CPU and memory are not shown (heqk does not report them); fleet and customer cards appear only when cloud-linked and say when the control plane has sent nothing. The incident story is `/investigate/:id`; until the device maps that path to the static page, links use `/investigate/incident/?id=<id>` (one helper, `store/routes.ts`). The story's model line says "device rules · no AI model" unless a planner explained it; no plan or alternative hypothesis is invented — the Copilot proposes one through PlanDiff.

**Shell components (os/mission-control/src/components).** `AppShell` (top bar, rail, banners, Copilot, phone tabs) wraps every route. `LeftRail` is the Layer 0 rail (five pillars), `AppRail` the Pro rail. `Drawer` is the one 400 px side panel. `Gate` does capability gating: granted renders, denied greys out with a reason, denied plus `hide` or unknown hides. `PlanDiff` is the plan viewer.

**Backend contract the UI codes against** (heqk serves these same-origin; until then the UI falls back honestly):

| Endpoint | Shape |
|---|---|
| `GET /api/capabilities` | `{"source":"manifest","schema":2,"granted":["ids","wan",…],"denied":{"openvswitch":"No Open vSwitch on this hardware"}}`. Anything in neither list is hidden. `/api/health` may also carry `capabilities: string[]`. Until the device answers, a sample manifest is used and every greyed reason says it is a sample. |
| `GET /api/planner/status` | `{"configured":bool,"endpoint":string\|null,"model":string\|null,"message"?:string}` |
| `POST /api/planner/propose` | body `{"intent":str}` → `{"answer","explanation":{"why","confidence","model"},"change":null\|{"before_plan","after_plan","diff":[{"kind":"added\|removed\|unchanged","text"}],"artifacts":[{"path","content"}],"warnings"},"warnings"}` |
| `POST /api/planner/approve` | body `{"artifacts":[…]}` → `{"staged":true,"proposal_id","staged_dir","artifact_count","note"}` |
| `GET /api/planner/proposals/:id` | `{"state":"staged\|applying\|verified\|failed","detail":str,"updated_ms":n}`. Drives Staged → Applying → Applied and verified. A 404 leaves the plan at Staged. |
