# Hookprobe UI Layouts & Technical Requirements

> Imported from the team's shared doc "Hookprobe UI Layouts & Technical Requirements" (revision 12, 10 Nov 2026), together with the "Hookprobe Wireframes" design canvas (incl. the "Advanced · signed configuration" page). `docs/architecture/MissionControl.md` stays canonical; this doc adds breakpoints, phone rules, the numbered requirements (TR, FR, DR, NFR) and the configuration journey. Repo-side decisions and verification notes are in the appendix at the end.


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

## Configuration journey: from flash to daily use

Today a customer can change only device access and Shield from Mission Control. Internet (DHCP, static, PPPoE), VLANs, Wi-Fi, prefix lists, ACLs and routes all live in **operator-signed files on the boot partition**. On the current kernel, Get Online is read-only: `/api/network` reports what was applied and says changes come from signed files. This section describes the repo as of commit `acd942c` (10 Nov 2026).

**Three authorities decide who can change what** (ADR 0053, ADR 0055)

| Authority | Who | What it can change | How long it lasts |
|---|---|---|---|
| Session action | Signed-in owner | Quarantine or release a device, pause Shield for one device for up to 1 h, allow a domain for up to 24 h, acknowledge an incident | Expires on its own (up to 7 days), lost on reboot |
| Owner rule (journal) | Owner, typing the owner key again and confirming "permanent" | `device_policy` (full, internet_only, lan_only, quarantine, blocked), `shield_allow`, `shield_block`, `shield_profile`, `device_label`; dry-run preview available | Durable, audited, HMAC-chained journal |
| Signed baseline | Operator's Ed25519 key, signing happens off the device | WAN, PPPoE, VLAN, management VLAN, Wi-Fi, prefix lists, ACLs, routes, SASE tunnel, block lists, IOC, rules | Until the next signed file; a generation number prevents rollback |

ADR 0055 D1 explicitly rules out WAN, VLAN, PPPoE, routes, ACLs and Wi-Fi credentials as owner rules.

**The journey stage by stage**

| Stage | What the customer does | Mechanism in the repo | Status |
|---|---|---|---|
| 1. Flash and provision | Gets a unit with a Wi-Fi label (QR) and a sealed owner-key card | `tools/provisioning/provision-unit.py`; the image is built by `os/build/make-cm5-heqk-disk.sh`, which can bake in signed WAN, POLICY, WIFI, DEVICES and list files | Built (factory station). The browser flasher in ADR 0037 is proposed |
| 2. First power-on | Joins `HookProbe-Setup-XXXX` with the per-device passphrase (`xxxx-xxxx-xxxx-xxxx`) | `apcred.rs`: credential derived from the device's sealing key, so there's no shared default (ADR 0054) | Built |
| 3. Sign in | Opens Mission Control on the setup network and enters the owner key | `POST /api/login`, HTTPS from the owner CA (ADR 0051) | Built |
| 4. Get online | Internet comes up as DHCP by default | `WAN.TXT` decides the mode; with no file, DHCP | DHCP works. The setup wizard (ADR 0010, `SystemSetupApp`) runs on mock data, and the kernel answers `/api/provision/launch` with "not implemented on heqk" |
| 5. Rename Wi-Fi | Wants their own SSID and password | Signed `WIFI.TXT` replaces the setup credential | Needs re-signing and re-flashing. Uploads of Wi-Fi files are refused (ADR 0056 D2) |
| 6. Organize devices | Puts kids' tablets on internet-only, blocks a camera | Owner journal (`POST /api/owner-rules`) or signed `DEVICES.TXT` | Works from Mission Control |
| 7. Tune Shield | Picks relaxed, balanced or strict, allows a site | Owner journal, or signed `BLOCK.TXT` / `ALLOW.TXT` with categories (ADR 0057) | Works from Mission Control |
| 8. Advanced network | PPPoE, ISP VLAN, management VLAN, firewall rules, failover routes | Signed `WAN.TXT` and `POLICY.TXT` | `POLICY.TXT` can be uploaded and applies on the next boot. `WAN.TXT` can't be uploaded |
| 9. Keep current | New block lists, threat intel, rules | `/api/upload` (begin, chunk, finish, activate): signed packs, A/B slots, rollback (ADR 0056) | Built for data packs; OS images are phase 2 |
| 10. Maintain | Rotate the owner key, factory reset | `POST /api/owner-key`, `POST /api/factory-reset` | Built |

**Every setting and where it lives**

| Setting | File | Keys or grammar | Change from Mission Control today? |
|---|---|---|---|
| Internet mode | `WAN.TXT` (`HQWAN1`) | `mode=dhcp`, `static` or `pppoe`; `ip=`, `gw=`, `dns=` for static | No: re-sign and re-flash |
| PPPoE login | `WAN.TXT` | `pppoe_user=`, `pppoe_pass=` | No |
| ISP VLAN and QinQ | `WAN.TXT` | `vlan=`, `vlan_outer=`, `pcp=` | No |
| Management VLAN | `WAN.TXT` | `mgmt_vlan=`, `mgmt_ip=`, `mgmt_gw=`, `mgmt_floor=` | No |
| Wi-Fi network | `WIFI.TXT` (`WIFI.SIG`) | `ssid=`, `psk=`, `channel=`, `security=` (wpa2, wpa3, wpa3-transition) | No. The parser has one SSID and no guest network |
| Prefix lists | `POLICY.TXT` (`HQPOL1`) | `prefix-list NAME seq N permit or deny PREFIX [ge n] [le n]` | Upload a signed file, applies on the next boot |
| ACLs | `POLICY.TXT` | `acl NAME seq N allow, block or drop PROTO SRC DST [PORT]`, `acl NAME default …`; stateful, first match, implicit drop | Same |
| Attach to interface | `POLICY.TXT` | `interface lan, eth1, wan or mgmt acl or prefix-list in or out NAME` | Same |
| Routes and failover | `POLICY.TXT` | `route DST [from SRC] via IF [gw ADDR] [metric N]`; two defaults with different metrics form a failover pair | Same |
| SASE tunnel | `POLICY.TXT` | `tunnel pop IP full` or `split PREFIX…` | Same |
| Device access | Owner journal, or `DEVICES.TXT` | `MAC policy [label] [shield=…]` | Yes, live |
| Shield lists and level | Owner journal, or `BLOCK.TXT` / `ALLOW.TXT` | `#! category=`, `#! level=` | Yes, live |
| IPv6 | Automatic | PPPoE IPV6CP, RA, DHCPv6-PD, stateful LAN firewall | Read-only status |

Signing is done off the device with `tools/policy-sign.py` (`sign`, `sign-wan`, `sign-devices`, `sign-blocklist`) using the operator key. Only the public key is compiled into the device image. An image built without a policy key is "standalone" and accepts an unsigned `POLICY.TXT`.

**What this means for the screens**

- **Get Online needs two depths.** The simple layer shows status (already possible from `/api/network`). Advanced becomes a configuration builder: a form that produces `WAN.TXT`, `WIFI.TXT` or `POLICY.TXT`, shows the change as a diff, then goes through sign, upload and activate on the next boot, with the generation number and a rollback.
- **Signing step: product decision needed.** The device never holds the operator's private key. Either the browser signs with a key the owner holds (WebCrypto or a hardware key, ADR 0053 option B), or the UI exports the draft for offline signing with `policy-sign.py` and the owner uploads the signed result.
- **Device and Shield changes stay instant.** They use the owner journal, with a "permanent" confirmation and a dry-run preview.

**Decision (Alina, 10 Nov 2026): the owner signs in the browser.** A signing key is provisioned during onboarding and held by the owner (a passkey, hardware key or browser-held key; it never leaves their control and is never stored on the device). Its public half becomes the device's operator key. Advanced changes then go: build the change, review the diff, sign in the browser, upload, apply on the next reboot, with rollback to the previous generation. This needs `/api/upload` to accept signed `WAN.TXT` and `WIFI.TXT` too (gap 1), and a way to enroll the owner's key as the policy key at first boot, since today that key is compiled into the image.

**Gaps to raise with the team**

1. `WAN.TXT` and `WIFI.TXT` can't be changed on a running device at all. A home user can't switch to PPPoE or rename Wi-Fi without re-flashing.
2. The first-run setup wizard (ADR 0010) is a mock in the UI; nothing on the kernel accepts its "Launch".
3. The policy header calls `POLICY.TXT` a file the AEGIS reconciler generates from intent, but I found no UI or API that writes it.
4. There's one SSID only: no guest network or second SSID, although the wireframes show one.
5. The generation floor that blocks rollback of an older policy is compile-time only. A persisted floor is deferred with RPMB (decision register, 8 Nov 2026).

### Verified against the repo (main, 2026-11-10)

Checked in code while integrating revision 12; these refine the section above.

| Statement in the section | What the code says | Where |
|---|---|---|
| Owner rules include `device_label` | Yes (G47): `device_label` by MAC, 1–31 printable ASCII (letters, digits, space `. _ - ' ( ) ,`); Rename in My Network previews, writes and reads it back. | `os/kernel/kernel/src/ownerapi.rs` |
| `device_policy` includes `blocked` | Not yet: `full`, `internet_only`, `lan_only`, `quarantine`. | `os/kernel/kernel/src/devpolicy.rs` |
| POLICY.TXT can be uploaded and applies on the next boot | Yes: upload types `wan`, `wifi`, `policy` are staged for the next boot (`applies: "next_boot"`), with owner rollback to the other verified half. Metal: config journey 20/20 (staged upload, rollback, reboot). Per-file uploads have **no** automatic revert. | `artstore.rs`, `docs/design/metal-evidence/20261111-batch59-63.md` |
| The generation floor is compile-time only | Partly outdated: the device-pinned trust anchor persists the POLICY floor in the DataVolume and raises it on every accepted policy (`anchor::raise_policy_floor`); RPMB hardening is what is deferred. | `os/kernel/kernel/src/anchor.rs` |
| The owner signs with a passkey or hardware key | Not with today's verifier: WebAuthn authenticators sign their own wrapped structure (authenticatorData + clientDataJSON), never the raw `HQ…` message the device checks. A browser-held Ed25519 key (or an imported `policy-sign.py` key) produces byte-identical signatures today; passkeys need a WebAuthn-aware verifier (ADR 0058). | `os/kernel/kernel/src/policysig.rs`, `wificfg.rs` |
| The owner's key becomes the device's operator key | Built (`/api/anchor/enroll`, `/rotate`; ADR 0058 D3): after enrollment only owner-signed configuration is accepted, the boot-card baseline still verifies with the vendor key, and a factory reset keeps the owner key (only a reflash clears it). Metal: journey B and D1 pass. Enrollment and rotation still await the operator / security review (gate SEC-05). | `anchor.rs`, `docs/design/metal-evidence/20261111-batch59-63.md` |
| A remote change reverts by itself if it breaks the internet | Only for a configuration **bundle** (HQCFG1, upload type `config`, ADR 0059 step 3): it boots as a trial, commits once the WAN works (or on the owner's confirm when it touches the management plane, `needs_confirm`), else reverts after 300 s. Metal: cfgd 13/13 including the automatic revert. Mission Control shows the trial banner with the countdown. | `cfgd`, `docs/design/metal-evidence/20261111-batch59-63.md` |

Signature formats a browser must produce (all 512 B, zero-padded, Ed25519 — `os/kernel/tools/policy-sign.py` is the reference):

| File | Signature file | Layout | Signed message |
|---|---|---|---|
| WAN.TXT (≤ 512 B, first line `HQWAN1`) | WAN.SIG | `HQNSIG1\0` · gen u64 LE · len u64 LE · sha256 · sig | `HQWAN1` · gen · len · sha256 |
| WIFI.TXT (≤ 1 KiB, `key=value`) | WIFI.SIG | `HQWSIG1\0` · gen · len · sha256 · sig | `HQWIF1` · gen · len · sha256 |
| POLICY.TXT (exactly 4096 B, starts `HQPOL1`, `\n`-padded) | POLICY.SIG | `HQPSIG1\0` · gen · sha256 · sig | `HQPOL1` · gen · sha256 |

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

**Pro batch 1 (Mission Control + Investigate).** Mission Control follows the wireframe's bento rows with only device-measured values: QSecBit, rules armed, devices watched, frames dropped, detection families, real engine hit counts, open incidents, time-bounded actions with their audit reason, WAN / device / LAN / Wi-Fi, packets seen / forwarded / dropped and retention. CPU and memory are not shown (heqk does not report them); fleet and customer cards appear only when cloud-linked and say when the control plane has sent nothing. The incident story is `/investigate/:id` (heqk serves the incident page for that path; `/investigate/incident/?id=<id>` still works; one helper, `store/routes.ts`). The story's model line says "device rules · no AI model" unless a planner explained it; no plan or alternative hypothesis is invented — the Copilot proposes one through PlanDiff.

**Pro batch 3 (Protect + owner rules).** Durable operator changes use the ADR 0055 owner-rules API, mapped onto the plan-as-diff flow: the device's `dry_run=1` preview is the plan; Approve writes it with `permanent=true` and an owner-key prompt (Staged); the GET read-back, matched by (kind, target) with seq ≥ the written seq, decides the outcome: **Applied and verified** only when the rule is `effective` on a device with a persistent journal; **Applied, but not kept across a restart** when `persistent` is false; **Failed** with the device's own `shadowed_by` reason when a pinned signed line wins. Removals verify by the row's absence. My Network's Move to zone and Protect's rules (block / allow a domain, remove) use it; renaming stays greyed (names come from DEVICES.TXT). Per-segment fail-open / fail-closed controls are not shown: the device does not report its fail mode.

**Pro batch 4 (Automate + Intelligence).** heqk runs no playbook engine, so Automate shows the built-in response pipeline it does run (ADR 0023: Detect, Validate, Contain, Notify, Recover, Verify, Close) with live counts per stage; containment is automatic and self-reverting, durable changes always wait for the owner. Custom playbooks and per-stage autonomy are greyed with that reason. The alert webhook (`/api/alert-hook`: ntfy / Gotify / JSON, minimum severity) is configurable as a durable owner write and read back. Intelligence shows the signed IOC pack and what actually matched on the network (known-bad TLS clients, Shield bypasses, IOC detections); CVE exposure renders only when the device or a control plane serves `/api/exploitability`, otherwise it says so; feed subscriptions (STIX/TAXII, MISP) are a control-plane feature, greyed with why.

**Pro batch 5 (Workspace + Administration).** The device keeps no per-user work, so Workspace records the screens and incidents you open and the items you pin in this browser, and says so; saved searches, AI conversations and draft playbooks appear once the device keeps them. Administration is wired to the device: the manifest's grants and denials with reasons; health and retention; the ADR 0056 signed-pack upload (container `X.SIG + X.TXT`, SHA-256 computed in the browser with a pure fallback for plain-HTTP devices, begin and activate each re-authenticate with the owner key, the device verifies digest, signature and anti-rollback); owner-key rotation; the planner's real status; the audit log; factory reset behind a typed ERASE, a reason and the owner key.

**Pro batch 6 (Customers + Business + Knowledge).** Customers is cloud-linked only: a standalone device says so and explains linking; a linked device with no tenant data says that. Business shows licensing on every device (HookProbe OS Community under the GNU AGPL-3.0, no account; offering it as a service or the account layer needs the commercial licence) and the signed packs it holds; billing and the marketplace are control-plane features, greyed with why. Knowledge ships real built-in runbooks (respond to an incident, move a device to a zone, update a signed pack, get alerts, lost owner key, keep more than the device holds), each linking to the screen it describes; authoring and the AI writer need a control plane's content service.

**Test loop.** Every screen above is covered by `os/mission-control/tests/ui` (130 checks, preview mode) and the device end-to-end `os/kernel/tools/mc-e2e.sh`; both run in gate g3 (`tools/ci/gates.sh g3`).

**Advanced signed configuration (ADR 0058, after revision 12).** Get Online → Advanced opens three editors as real routes — Internet `/network/wan/advanced` (WAN.TXT), Wi-Fi `/network/wifi` (WIFI.TXT), Firewall and routes `/protect/policies` (POLICY.TXT, 4096 B) — validated exactly as the device parses them, with the exact file shown as a draft (secrets masked). Review shows the diff against what the device reports; signing happens in the browser with the owner's Ed25519 key (Administration → Signing key: create, or import a `policy-sign.py` PEM; PEM backup), byte-identical to `policy-sign.py` (checked in the UI suite). Upload goes to `/api/upload` with type `wan` / `wifi` / `policy`; until the device serves those types it answers that it doesn't accept the file yet, and the two signed files are offered for the boot card. Passkeys / security keys are not offered: WebAuthn signatures are not what the device verifies (ADR 0058 D4).

**Shell components (os/mission-control/src/components).** `AppShell` (top bar, rail, banners, Copilot, phone tabs) wraps every route. `LeftRail` is the Layer 0 rail (five pillars), `AppRail` the Pro rail. `Drawer` is the one 400 px side panel. `Gate` does capability gating: granted renders, denied greys out with a reason, denied plus `hide` or unknown hides. `PlanDiff` is the plan viewer.

**Backend contract the UI codes against** (heqk serves these same-origin; until then the UI falls back honestly):

| Endpoint | Shape |
|---|---|
| `GET /api/capabilities` | `{"source":"manifest","schema":2,"granted":["ids","wan",…],"denied":{"openvswitch":"No Open vSwitch on this hardware"}}`. Anything in neither list is hidden. `/api/health` may also carry `capabilities: string[]`. Until the device answers, a sample manifest is used and every greyed reason says it is a sample. |
| `GET /api/planner/status` | `{"configured":bool,"endpoint":string\|null,"model":string\|null,"message"?:string}` |
| `POST /api/planner/propose` | body `{"intent":str}` → `{"answer","explanation":{"why","confidence","model"},"change":null\|{"before_plan","after_plan","diff":[{"kind":"added\|removed\|unchanged","text"}],"artifacts":[{"path","content"}],"warnings"},"warnings"}` |
| `POST /api/planner/approve` | body `{"artifacts":[…]}` → `{"staged":true,"proposal_id","staged_dir","artifact_count","note"}` |
| `GET /api/planner/proposals/:id` | `{"state":"staged\|applying\|verified\|failed","detail":str,"updated_ms":n}`. Drives Staged → Applying → Applied and verified. A 404 leaves the plan at Staged. |
