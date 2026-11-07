# security/redteam/ — the ADR 0020 adversarial-resilience harness

**Read `docs/adr/0020-adversarial-resilience-harness.md` FULLY first.** This directory is a
DEV/CI-ONLY tool. It is NEVER staged into a shipped image, NEVER listed in the module registry
(`modules/*/module.yaml`), and structurally incapable of targeting anything but a declared,
isolated DUT (device-under-test). If you are looking for a way to point this at a real network —
stop; that is exactly what it is designed to refuse to do.

## What this is

An automated, ROE-gated "inward pentester": it re-attacks HookProbe's OWN detection stack
(napse-dpi's L1/L2 defensive detectors, the L4 port-scan/handshake-confirmation gate,
napse-quarantine's bounded enforced set) inside a network namespace it creates itself, and records
whether each defense withstood or was breached into the SAME evidence graph an operator's incidents
live in (`crates/hookprobe-evidence`). It is the automation of the manual Kali-container-attacks-
the-Pi campaign that hardened ADR 0018 — a hand-run campaign catches a regression once; this makes
it catch one every release (Gate R).

## Topology (the ONLY topology this tool will ever transmit into)

```
                 host netns                         hookprobe-dut netns
            (this dev box / CI runner)              (created by netns-dut.sh)
   +-----------------------------+            +----------------------------------+
   |  redteam-engine / probes    |            |  napse-dpi (REAL binary, same    |
   |  10.99.0.1/24  veth-dut  <--|--- veth ---|--> veth-dut-peer  10.99.0.2/24    |
   |                             |   pair     |  one it ships) capturing on the   |
   |  target_guard asserts THIS  |            |  peer iface; NO default route,    |
   |  exact topology via `ip -j` |            |  NO route off this veth — even a  |
   |  before any send (D3 cond2)|            |  target_guard bug can't escape    |
   +-----------------------------+            +----------------------------------+
```

**This topology is asserted, not trusted.** `engine/src/topology.rs` independently queries the
kernel (`ip -j`, itself a netlink client) before any L2/broadcast probe is allowed to fire: the
egress interface must be `kind==veth`, its peer must be netlink-verified resident in the declared
netns, and that netns must carry no default route. Two independent failures are required for a
frame to ever leave this topology (ADR 0020 D3 condition 2 / the abuse-analysis "netns topology
isolation" row).

**Never run this against a shared/mgmt segment.** ADR 0020 D3 condition 6 (the single largest
residual risk per the 2026-07-05 security-auditor sign-off): a destructive L1/L2 flood on a shared
mgmt segment would DoS the operator's own SSH to both the DUT and the dev box. There is no
hardware-in-the-loop target class configured anywhere in this tree today — adding one needs a
dedicated link/VLAN descriptor off the mgmt path and a fresh security-auditor review.

## The six threat-model conditions (2026-07-05 sign-off) — where each is enforced

| # | Condition | Enforced in |
|---|---|---|
| 1 | `limits:` block mandatory, fail-closed on breach | `rules-of-engagement.yaml` (`limits:`) + `engine/src/roe.rs::validate` (refuses to start on a missing/zero field) + `engine/src/limiter.rs` (checked per frame) |
| 2 | L2 topology asserted via netlink, never trusted from config | `engine/src/topology.rs::assert_l2_veth_topology` |
| 3 | IP/CIDR literals only, DNS resolution forbidden | `engine/src/roe.rs::parse_cidr_literal` (the ONLY place a string becomes an `IpAddr`, ever) + `hard_deny.dns_resolution` enforced-true at load |
| 4 | No blocklist/feed write path in Phase-1 | `engine/src/findings.rs` — the ONLY output is `attack_run`/`finding` JSON; no enforcement call exists anywhere in this crate |
| 5 | Every campaign audited pre-fire; kill-switch honored | `engine/src/campaign.rs::start` (writes BEFORE any probe) + `engine/src/kill_switch.rs` |
| 6 | Destructive L1/L2 floods run against netns/QEMU by default; no shared mgmt-segment HIL | `dut/netns-dut.sh` (netns/veth only) — no HIL target class exists in this tree |

## Running a lab campaign

```sh
# 1. Stand up the DUT (needs CAP_NET_ADMIN/root; SKIPs honestly if unavailable):
security/redteam/dut/netns-dut.sh up
security/redteam/dut/netns-dut.sh status   # prove the topology (no default route, kind=veth, peer in netns)

# 2. Fire ONE probe through the ROE-gated engine (needs CAP_NET_RAW/root for the raw send):
cargo run -p redteam-engine --bin redteam-engine -- \
  --roe security/redteam/rules-of-engagement.yaml \
  --out /tmp/redteam-out --probe mac-flood \
  --iface veth-dut --netns hookprobe-dut --count 200 \
  --events /tmp/redteam-dut-events.jsonl --verify-substr l2_mac_flood

cargo run -p redteam-engine --bin redteam-engine -- \
  --roe security/redteam/rules-of-engagement.yaml \
  --out /tmp/redteam-out --probe syn-scan \
  --iface veth-dut --target 10.99.0.2 --ports 2000,2001,...,2054 \
  --events /tmp/redteam-dut-events.jsonl --verify-substr port_scan

# 3. Ingest the resulting evidence (same ingest path release.json/beacon.json use):
cargo run -p hookprobe-evidence -- --db /tmp/redteam-evidence.db \
  --ingest-attack-run /tmp/redteam-out/attack_run.json \
  --ingest-findings /tmp/redteam-out/findings.jsonl

# 4. Tear down:
security/redteam/dut/netns-dut.sh down
```

## Directory map

- `rules-of-engagement.yaml` — the enforced scope contract (D3); default-deny.
- `engine/` — the Rust+tokio campaign runner: `roe`/`topology`/`limiter`/`kill_switch`/
  `target_guard`/`findings`/`campaign`, plus the `l2_link`/`l34_net`/`l56_session`/`l7_app` probe
  modules (declared here as `#[path]`-included modules of the ONE crate, per D4 — "a native engine
  keeps ROE enforcement in-process, ahead of the socket").
- `probes/` — the probe implementations + shared `packet.rs`/`sockets.rs` helpers (source lives
  here per the ADR's literal directory layout; compiled as part of the `engine` crate).
- `targets/*.yaml` — per-DUT-component descriptors (which telemetry proves a defense fired, RED
  thresholds). `hydra.yaml`/`qsecbit.yaml` are `status: roadmap` (no built attack surface yet);
  `htp.yaml` is a permanent roadmap placeholder (ADR 0004 is design-only).
- `schema/finding.schema.json` — the JSON Schema for one `finding` line.
- `dut/netns-dut.sh` — stands up the netns/veth DUT and (if built) the REAL `napse-dpi` binary
  inside it. `dut/manifest.dut.json` is a synthetic, UNSIGNED Platform Manifest used ONLY to grant
  `napse-dpi` the `capture` capability inside this lab netns — never used for anything else, never
  shipped, never presented as a real device identity.

## What's phase-active vs roadmap in this pass

| Probe | Status |
|---|---|
| `l2_link::mac_flood` | **built** — real AF_PACKET send, validates `napse_loader::l2guard::MacFloodTracker` |
| `l34_net::syn_scan::run_fan_out_scan` | **built** — validates `napse_loader::portscan::PortScanTracker` |
| `l34_net::syn_scan::run_state_exhaustion` | **built** (smoke-level proxy — see its doc comment: verifies detection still fires under volume, not yet a full bounded-set-size assertion) |
| `l2_link::roadmap::{arp_spoof, broadcast_amplification, frame_vlan_fuzz, wifi_80211_frame_forgery}` | **ROADMAP** — declared, refuse-with-reason, never fabricate a pass |
| `l34_net::roadmap::{wan_ingress_spoof, frag_overlap}` | **ROADMAP** — `wan_ingress_spoof` needs a dual-homed WAN+LAN DUT topology this harness does not yet provide |
| L5/L6 (`l56_session`) | **ROADMAP** — HTP is design-only (ADR 0004); dashboard-TLS/signing-downgrade are phase-2 |
| L7 (`l7_app`) | **ROADMAP** — phase-2/3 per ADR 0020 D8 |

## The propagation loop (hunt → detect-or-miss → record `finding` → detection improvement → registry → all images → re-hunt)

This harness deliberately adds **zero new propagation machinery** — the loop closes entirely through
mechanisms ADR 0014/0015 already built:

1. **Hunt:** a campaign fires `mac-flood`/`syn-scan` (etc.) against the netns DUT's REAL `napse-dpi`.
2. **Detect-or-miss:** `napse-dpi` either emits a matching alert (`category=mac_flood`/`port_scan`,
   read from `EVENTS`) or it doesn't; the engine's `--verify-substr` check turns that into
   `withstood`/`breached`/`inconclusive`.
3. **Record `finding`:** `hookprobe-evidence --ingest-attack-run/--ingest-findings` lands the result
   as `attack_runs`/`findings` nodes, e.g. `target_component: "napse-dpi"`. A `breached` finding also
   gets a `breached` edge to `component:napse-dpi`, and (via the SAME `link_feedback`/`informed_by`
   mechanism ADR 0011 D1 already ships) can be turned into a `requirement` the way the dnsxai
   gap-close (ADR 0014) was.
4. **Detection improvement:** a `code-developer` fix lands in the SAME source tree that already
   ships the detector — `modules/napse-capture/loader/src/{l2guard.rs,portscan.rs,dpi.rs}` — because
   `napse-dpi` is the binary the fired probe's `target_component` names.
5. **Registry (ADR 0015):** `modules/napse-capture/module.yaml` is ALREADY the registry entry that
   stages `napse-dpi` into every arch/profile image (`id: napse-capture`, `staging:` block). Nothing
   about the fix requires touching that file — the fix is inside the crate the registry entry already
   points at.
6. **All images:** the next `builder/gen-staging.sh` run picks up the rebuilt `napse-dpi` binary
   through the EXACT SAME `staging.artifacts` path every other release build already uses. "Fix
   once → in all images" is therefore a property of ADR 0015's existing registry-driven inclusion,
   not a new mechanism this ADR had to invent.
7. **Re-hunt:** the next Gate R run (or the next `--gate-r` campaign) fires the SAME probe again; a
   previously-`breached` finding for the SAME probe/target_component pair becomes `withstood` once
   the fix ships, closing the loop the way the dnsxai before/after (ADR 0014) did for DNS.

This is the concrete "finding → detection-rule mapping that `gen-staging` would carry into all
images" the loop promises: the mapping IS `finding.target_component` → the `modules/<id>/module.yaml`
whose `id` names that component — already a total function today (every phase-active probe's
`target_component` is `napse-dpi`/`napse-quarantine`, both registered modules), so no new
lookup table is needed for it to hold.

## Gate R

`builder/gate-ladder.sh --gate-r` and `builder/release-pass.sh` wire this harness into the release
gate ladder (ADR 0020 D5). See their own header comments for the exact SKIP-with-reason conditions
(no netns/CAP_NET_ADMIN/CAP_NET_RAW available) and the fail-closed RED-breach behavior.
